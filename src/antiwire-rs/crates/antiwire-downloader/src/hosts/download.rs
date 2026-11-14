use std::path::Path;

use antiwire_policy::{HostsParser, HostsParserMode};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{info, warn};

use crate::error::{aggregate_mirror_errors, map_stream_io_error, DownloadError};
use crate::hosts::hash::{
    fetch_remote_hash, hex_digest, list_url_for_hash, parse_hash_file, sidecar_path,
    stamp_is_fresh, stamp_path, write_text_file,
};
use crate::response::{limited_body, send};
use crate::writer::AtomicWriter;
use crate::{DownloadConfig, HostsDownloadItem};

const MAX_LINE_BYTES: usize = 64 * 1024;
const WRITE_FLUSH_BYTES: usize = 64 * 1024;

pub(crate) async fn download_hosts_list(
    client: &antiwire_http::HttpClient,
    item: &HostsDownloadItem,
    config: &DownloadConfig,
) -> Result<bool, DownloadError> {
    if let Some(parent) = item.dest_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    if item.hash_urls.is_empty() {
        return download_unhashed_list(client, item, config).await;
    }

    download_hashed_list(client, item, config).await
}

async fn download_unhashed_list(
    client: &antiwire_http::HttpClient,
    item: &HostsDownloadItem,
    config: &DownloadConfig,
) -> Result<bool, DownloadError> {
    let mut attempts = Vec::new();
    for (index, url) in item.urls.iter().enumerate() {
        match download_hosts_list_from_url(
            client,
            url,
            &item.dest_path,
            item.parser_mode,
            config,
            None,
        )
        .await
        {
            Ok(()) => {
                if index > 0 {
                    info!(
                        name = %item.name,
                        url = %url,
                        attempt = index + 1,
                        "blocklist mirror succeeded"
                    );
                }
                return Ok(true);
            }
            Err(error) => {
                warn!(
                    name = %item.name,
                    url = %url,
                    attempt = index + 1,
                    error = %error,
                    "blocklist mirror failed"
                );
                attempts.push((url.clone(), error));
            }
        }
    }
    Err(aggregate_mirror_errors(&item.name, attempts))
}

async fn download_hashed_list(
    client: &antiwire_http::HttpClient,
    item: &HostsDownloadItem,
    config: &DownloadConfig,
) -> Result<bool, DownloadError> {
    let sidecar = sidecar_path(&item.dest_path);
    let stamp = stamp_path(&item.dest_path);
    let dest_exists = item.dest_path.exists();

    if dest_exists && stamp_is_fresh(&stamp) {
        if let Ok(local) = tokio::fs::read_to_string(&sidecar).await {
            if parse_hash_file(&local).is_some() {
                return Ok(false);
            }
        }
    }

    let mut attempts = Vec::new();
    let mut saw_hash = false;
    for hash_url in &item.hash_urls {
        let Some(list_url) = list_url_for_hash(hash_url, &item.urls) else {
            continue;
        };
        let remote_hash = match fetch_remote_hash(client, hash_url, config).await {
            Ok(remote_hash) => remote_hash,
            Err(error) => {
                warn!(
                    name = %item.name,
                    url = %hash_url,
                    error = %error,
                    "hashed blocklist hash fetch failed"
                );
                attempts.push((hash_url.clone(), error));
                continue;
            }
        };
        saw_hash = true;

        if dest_exists {
            if let Ok(local) = tokio::fs::read_to_string(&sidecar).await {
                if parse_hash_file(&local).as_ref() == Some(&remote_hash) {
                    let _ = write_text_file(&stamp, "").await;
                    return Ok(false);
                }
            }
        }

        match download_verified_list(client, list_url, &remote_hash, item, config).await {
            Ok(()) => {
                let file_name = item
                    .dest_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("list.txt");
                let _ = write_text_file(&sidecar, &format!("{remote_hash}  {file_name}\n")).await;
                let _ = write_text_file(&stamp, "").await;
                return Ok(true);
            }
            Err(error) => {
                warn!(
                    name = %item.name,
                    url = %list_url,
                    error = %error,
                    "hashed blocklist mirror failed"
                );
                attempts.push((list_url.to_owned(), error));
            }
        }
    }

    if dest_exists && !saw_hash {
        return Ok(false);
    }
    Err(aggregate_mirror_errors(&item.name, attempts))
}

/// Streams the list into a staged file while hashing it, and commits only when
/// the body matches `expected_hash`. Nothing larger than one line is held in
/// memory, however big the list.
async fn download_verified_list(
    client: &antiwire_http::HttpClient,
    url: &str,
    expected_hash: &str,
    item: &HostsDownloadItem,
    config: &DownloadConfig,
) -> Result<(), DownloadError> {
    download_hosts_list_from_url(
        client,
        url,
        &item.dest_path,
        item.parser_mode,
        config,
        Some(expected_hash),
    )
    .await
}

async fn download_hosts_list_from_url(
    client: &antiwire_http::HttpClient,
    url: &str,
    dest_path: &Path,
    parser_mode: HostsParserMode,
    config: &DownloadConfig,
    expected_hash: Option<&str>,
) -> Result<(), DownloadError> {
    let response = send(client.get(url)?, config).await?;
    let writer = AtomicWriter::new(dest_path.to_path_buf());

    let result = async {
        let mut line_reader = BufReader::new(limited_body(response, config.max_bytes));
        let mut line_buf = Vec::new();
        let mut write_buf = Vec::with_capacity(WRITE_FLUSH_BYTES);
        let mut skipping_oversized = false;
        // A captive portal or an error page served with 200 parses to nothing.
        // Committing that would replace a good list with an empty one.
        let mut wrote_domain = false;
        // Hashes the raw body, every byte as it is consumed, so verification
        // needs no second copy of the list.
        let mut hasher = expected_hash.map(|_| Sha256::new());

        loop {
            let available =
                match tokio::time::timeout(config.idle_timeout, line_reader.fill_buf()).await {
                    Ok(Ok(buf)) => buf,
                    Ok(Err(error)) => {
                        let limit_exceeded = line_reader.get_ref().limit_exceeded();
                        return Err(map_stream_io_error(error, limit_exceeded, config.max_bytes));
                    }
                    Err(_) => return Err(DownloadError::IdleTimeout),
                };

            if available.is_empty() {
                if !line_buf.is_empty() && !skipping_oversized {
                    let line = String::from_utf8_lossy(&line_buf);
                    let cleaned = cleaned_line(&line, parser_mode);
                    if !cleaned.is_empty() {
                        wrote_domain = true;
                        write_buf.extend_from_slice(&cleaned);
                    }
                }
                break;
            }

            if let Some(newline_pos) = available.iter().position(|&b| b == b'\n') {
                let chunk = &available[..newline_pos];
                let consume_len = newline_pos + 1;
                // Only this line is consumed; the rest of the buffer is
                // returned again by the next `fill_buf`.
                if let Some(hasher) = hasher.as_mut() {
                    hasher.update(&available[..consume_len]);
                }

                if skipping_oversized {
                    skipping_oversized = false;
                    line_buf.clear();
                } else {
                    line_buf.extend_from_slice(chunk);
                    let line = String::from_utf8_lossy(&line_buf);
                    let cleaned = cleaned_line(&line, parser_mode);
                    if !cleaned.is_empty() {
                        wrote_domain = true;
                        write_buf.extend_from_slice(&cleaned);
                        if write_buf.len() >= WRITE_FLUSH_BYTES {
                            writer
                                .write(std::mem::take(&mut write_buf))
                                .await
                                .map_err(DownloadError::from)?;
                        }
                    }
                    line_buf.clear();
                }
                line_reader.consume(consume_len);
            } else {
                let chunk_len = available.len();
                if let Some(hasher) = hasher.as_mut() {
                    hasher.update(available);
                }
                if skipping_oversized {
                    line_reader.consume(chunk_len);
                } else if line_buf.len().saturating_add(chunk_len) > MAX_LINE_BYTES {
                    skipping_oversized = true;
                    line_buf.clear();
                    line_reader.consume(chunk_len);
                } else {
                    line_buf.extend_from_slice(available);
                    line_reader.consume(chunk_len);
                }
            }
        }

        // Returning before the commit drops the staged file; the existing
        // list stays in place.
        if let (Some(hasher), Some(expected)) = (hasher, expected_hash) {
            if hex_digest(hasher) != expected {
                return Err(DownloadError::HashMismatch);
            }
        }
        if !wrote_domain {
            return Err(DownloadError::EmptyList);
        }
        if !write_buf.is_empty() {
            writer.write(write_buf).await.map_err(DownloadError::from)?;
        }

        writer.commit().await.map_err(DownloadError::from)?;
        Ok(())
    }
    .await;

    writer.complete(result).await
}

fn cleaned_line(line: &str, mode: HostsParserMode) -> Vec<u8> {
    let mut output = Vec::new();
    HostsParser::for_each_line_domain(line, mode, |domain| {
        output.extend_from_slice(domain.as_bytes());
        output.push(b'\n');
    });
    output
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::download_hosts_list;
    use crate::client::DownloadClient;
    use crate::hosts::batch::download_hosts_batch;
    use crate::hosts::hash::sha256_hex;
    use crate::{DownloadConfig, HostsDownloadItem};
    use antiwire_policy::HostsParserMode;
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

    fn item(name: &str, urls: Vec<String>, dest_path: std::path::PathBuf) -> HostsDownloadItem {
        HostsDownloadItem {
            name: name.to_owned(),
            urls,
            hash_urls: Vec::new(),
            dest_path,
            parser_mode: HostsParserMode::RequireHostsAddress,
        }
    }

    #[tokio::test]
    async fn download_hosts_list_streams_and_cleans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("cleaned.txt");
        let url = spawn_http_server(|| {
            b"0.0.0.0 ads.example.com\n# comment\n0.0.0.0 tracker.example.com\n".to_vec()
        })
        .await;

        let client = DownloadClient::for_local_tests();
        let download_item = item("test", vec![url], dest.clone());
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(5),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("download");

        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("ads.example.com"));
        assert!(content.contains("tracker.example.com"));
        assert!(!content.contains('#'));
    }

    #[tokio::test]
    async fn download_cleans_mixed_blocklist_formats() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("mixed.txt");
        let url = spawn_http_server(|| {
            b"||ads.example.com^\nlocal=/tracker.example.com/\n*.wildcard.example.com\n".to_vec()
        })
        .await;

        let client = DownloadClient::for_local_tests();
        let download_item = HostsDownloadItem {
            name: "mixed".to_owned(),
            urls: vec![url],
            hash_urls: Vec::new(),
            dest_path: dest.clone(),
            parser_mode: HostsParserMode::AllowBareDomains,
        };
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("download");

        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("ads.example.com"));
        assert!(content.contains("tracker.example.com"));
        assert!(content.contains("wildcard.example.com"));
        assert!(!content.contains("||"));
        assert!(!content.contains("local=/"));
        assert!(!content.contains('*'));
    }

    #[tokio::test]
    async fn fallback_uses_second_mirror_on_first_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("mirror.txt");
        let good_url = spawn_http_server(|| b"0.0.0.0 mirror.example.com\n".to_vec()).await;

        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "mirror-test",
            vec!["http://127.0.0.1:1/".to_owned(), good_url],
            dest.clone(),
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(2),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("fallback download");

        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("mirror.example.com"));
    }

    #[tokio::test]
    async fn fallback_fails_once_when_all_mirrors_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "all-fail",
            vec![
                "http://127.0.0.1:1/".to_owned(),
                "http://127.0.0.1:2/".to_owned(),
            ],
            dir.path().join("fail.txt"),
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(2),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("all mirrors should fail");
        assert!(matches!(
            error,
            crate::DownloadError::AllMirrorsFailed { .. }
        ));

        let outcomes = download_hosts_batch(&client, &[download_item], &config, 1).await;
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].result.is_err());
    }

    #[tokio::test]
    async fn idle_timeout_fails_on_stall() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let partial = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello";
                let _ = socket.write_all(partial.as_bytes()).await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "stall",
            vec![format!("http://{addr}/")],
            dir.path().join("stall.txt"),
        );
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_millis(100),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("stall");
        assert!(matches!(error, crate::DownloadError::IdleTimeout));
    }

    #[tokio::test]
    async fn idle_timeout_resets_on_progress() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let line1 = "0.0.0.0 a.example.com\n";
                let line2 = "0.0.0.0 b.example.com\n";
                let body_len = line1.len() + line2.len();
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n"
                );
                let _ = socket.write_all(header.as_bytes()).await;
                let _ = socket.write_all(line1.as_bytes()).await;
                tokio::time::sleep(Duration::from_millis(150)).await;
                let _ = socket.write_all(line2.as_bytes()).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("progress.txt");
        let client = DownloadClient::for_local_tests();
        let download_item = item("progress", vec![format!("http://{addr}/")], dest.clone());
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_millis(250),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("progress download");
        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("a.example.com"));
        assert!(content.contains("b.example.com"));
    }

    #[tokio::test]
    async fn download_aborts_when_size_limit_exceeded() {
        let url = spawn_http_server(|| vec![b'x'; 32]).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item("big", vec![url], dir.path().join("big.txt"));
        let config = DownloadConfig {
            max_bytes: 16,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("size limit");
        assert!(matches!(error, crate::DownloadError::SizeLimitExceeded(16)));
    }

    #[tokio::test]
    async fn concurrent_downloads_to_same_destination_commit_whole_files() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            for index in 0..2 {
                let (mut socket, _) = listener.accept().await.expect("accept");
                tokio::spawn(async move {
                    drain_http_request(&mut socket).await;
                    let domain = if index == 0 {
                        "first.example"
                    } else {
                        "second.example"
                    };
                    let body = format!("0.0.0.0 {domain}\n");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.expect("header");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    socket.write_all(body.as_bytes()).await.expect("body");
                });
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let destination = dir.path().join("shared.txt");
        let make_item =
            |name: &str| item(name, vec![format!("http://{addr}/")], destination.clone());
        let first = make_item("first");
        let second = make_item("second");
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };
        let client = DownloadClient::for_local_tests();

        let (first_result, second_result) = tokio::join!(
            download_hosts_list(&client.inner, &first, &config),
            download_hosts_list(&client.inner, &second, &config)
        );
        first_result.expect("first download");
        second_result.expect("second download");

        let contents = tokio::fs::read_to_string(destination)
            .await
            .expect("read committed file");
        assert!(
            contents == "first.example\n" || contents == "second.example\n",
            "atomic replacement must expose one complete download: {contents:?}"
        );
    }

    #[tokio::test]
    async fn batch_respects_parallel_limit() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let active_accept = Arc::clone(&active);
        let peak_accept = Arc::clone(&peak);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let now = active_accept.fetch_add(1, Ordering::SeqCst) + 1;
                peak_accept.fetch_max(now, Ordering::SeqCst);
                let active_done = Arc::clone(&active_accept);
                tokio::spawn(async move {
                    drain_http_request(&mut socket).await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    let body = b"0.0.0.0 parallel.example.com\n";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.write_all(body).await;
                    active_done.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let items: Vec<HostsDownloadItem> = (0..6)
            .map(|index| HostsDownloadItem {
                name: format!("list-{index}"),
                urls: vec![format!("http://{addr}/")],
                hash_urls: Vec::new(),
                dest_path: dir.path().join(format!("list-{index}.txt")),
                parser_mode: HostsParserMode::RequireHostsAddress,
            })
            .collect();
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let outcomes = download_hosts_batch(&client, &items, &config, 3).await;
        assert_eq!(outcomes.len(), 6);
        assert!(outcomes.iter().all(|outcome| outcome.result.is_ok()));
        assert!(peak.load(Ordering::SeqCst) <= 3);
    }

    #[tokio::test]
    async fn header_stall_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                // Never send any response headers; stall the connection
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "header-stall",
            vec![format!("http://{addr}/")],
            dir.path().join("header_stall.txt"),
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_millis(150),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("should time out on stalled headers");
        assert!(matches!(error, crate::DownloadError::IdleTimeout));
    }

    #[tokio::test]
    async fn non_utf8_comments_are_gracefully_handled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("non_utf8.txt");
        // Non-UTF8 byte 0xE9 (é in Latin-1) and 0xFF
        let mut body = b"0.0.0.0 valid.example.com # comment with \xE9 and \xFF\n".to_vec();
        body.extend_from_slice(b"0.0.0.0 second.example.com\n");
        let url = spawn_http_server(move || body.clone()).await;

        let client = DownloadClient::for_local_tests();
        let download_item = item("non-utf8", vec![url], dest.clone());
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("non-utf8 comments should not fail download");

        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("valid.example.com"));
        assert!(content.contains("second.example.com"));
    }

    #[tokio::test]
    async fn oversized_line_is_safely_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("oversized.txt");
        // Line exceeding 64KB without newline
        let mut body = vec![b'a'; 70 * 1024];
        body.push(b'\n');
        body.extend_from_slice(b"0.0.0.0 normal.example.com\n");
        let url = spawn_http_server(move || body.clone()).await;

        let client = DownloadClient::for_local_tests();
        let download_item = item("oversized", vec![url], dest.clone());
        let config = DownloadConfig {
            max_bytes: 128 * 1024,
            idle_timeout: Duration::from_secs(5),
        };

        download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("oversized line should be safely bounded without error");

        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("normal.example.com"));
    }

    /// The production client may reach the user's own network, for custom lists
    /// hosted there, but never this machine or a metadata service.
    #[tokio::test]
    async fn blocklist_client_refuses_loopback_and_metadata_urls() {
        let client = DownloadClient::new();
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        for url in [
            "http://127.0.0.1:9/list.txt",
            "http://[::1]:9/list.txt",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            let download_item = item("refused", vec![url.to_owned()], dir.path().join("x.txt"));
            let err = download_hosts_list(&client.inner, &download_item, &config)
                .await
                .expect_err("refused");
            assert!(
                matches!(err, crate::DownloadError::Refused(_)),
                "{url}: {err:?}"
            );
        }
        assert!(client.inner.get("http://192.168.1.20/hosts.txt").is_ok());
        assert!(DownloadClient::public_only()
            .inner
            .get("http://192.168.1.20/hosts.txt")
            .is_err());
    }

    #[tokio::test]
    async fn redirect_to_cloud_metadata_is_blocked() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let response =
                    "HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "metadata-ssrf",
            vec![format!("http://{addr}/redirect")],
            dir.path().join("metadata.txt"),
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let err = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("redirect to cloud metadata must be blocked");
        assert!(matches!(err, crate::DownloadError::Http(_)));
    }

    #[tokio::test]
    async fn redirect_loop_is_terminated_safely() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    drain_http_request(&mut socket).await;
                    let response =
                        "HTTP/1.1 302 Found\r\nLocation: /loop\r\nConnection: close\r\n\r\n";
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let download_item = item(
            "loop-test",
            vec![format!("http://{addr}/loop")],
            dir.path().join("loop.txt"),
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let err = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("redirect loop should be terminated");
        assert!(matches!(err, crate::DownloadError::Http(_)));
    }

    #[tokio::test]
    async fn failed_download_does_not_corrupt_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("existing.txt");
        tokio::fs::write(&dest, b"original content that must not be corrupted\n")
            .await
            .expect("write original");

        let url = spawn_http_server(|| vec![b'z'; 512]).await;
        let client = DownloadClient::for_local_tests();
        let download_item = item("abort-test", vec![url], dest.clone());
        let config = DownloadConfig {
            max_bytes: 64,
            idle_timeout: Duration::from_secs(5),
        };

        let err = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("should fail size limit");
        assert!(matches!(err, crate::DownloadError::SizeLimitExceeded(64)));

        let content = tokio::fs::read_to_string(&dest)
            .await
            .expect("read destination");
        assert_eq!(content, "original content that must not be corrupted\n");
    }

    /// The regression this guards: a captive portal answering 200 with an HTML page
    /// used to replace a good list with an empty one.
    #[tokio::test]
    async fn page_without_domains_keeps_the_existing_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("existing.txt");
        tokio::fs::write(
            &dest,
            b"ads.example.com
",
        )
        .await
        .expect("write original");

        let url = spawn_http_server(|| {
            b"<html><body>Sign in to the hotel Wi-Fi</body></html>
"
            .to_vec()
        })
        .await;
        let client = DownloadClient::for_local_tests();
        let download_item = item("portal", vec![url], dest.clone());
        let config = DownloadConfig {
            max_bytes: 1024,
            idle_timeout: Duration::from_secs(5),
        };

        let err = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("a page with no domains must be rejected");
        assert!(matches!(err, crate::DownloadError::EmptyList), "{err:?}");
        let content = tokio::fs::read_to_string(&dest).await.expect("read");
        assert_eq!(
            content,
            "ads.example.com
"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).expect("list").count(),
            1,
            "no staged file is left behind"
        );
    }

    #[tokio::test]
    async fn http_status_error_aborts_without_creating_destination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                drain_http_request(&mut socket).await;
                let response =
                    "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("not_found.txt");
        let client = DownloadClient::for_local_tests();
        let download_item = item("404-test", vec![format!("http://{addr}/")], dest.clone());
        let config = DownloadConfig::default();

        let err = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("404 should error");
        assert!(matches!(err, crate::DownloadError::Http(_)));
        assert!(
            !dest.exists(),
            "destination file must not exist on 404 error"
        );
    }

    async fn request_path(socket: &mut tokio::net::TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let read = socket.read(&mut chunk).await.expect("read request chunk");
            if read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..read]);
            if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_owned()
    }

    async fn spawn_hash_and_list_server(
        hash_body: String,
        list_body: Vec<u8>,
    ) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let hash_hits = Arc::new(AtomicUsize::new(0));
        let list_hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let hash_hits_task = Arc::clone(&hash_hits);
        let list_hits_task = Arc::clone(&list_hits);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let path = request_path(&mut socket).await;
                let body = if path.starts_with("/hash") {
                    hash_hits_task.fetch_add(1, Ordering::SeqCst);
                    hash_body.as_bytes().to_vec()
                } else {
                    list_hits_task.fetch_add(1, Ordering::SeqCst);
                    list_body.clone()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
        });
        (format!("http://{addr}"), hash_hits, list_hits)
    }

    fn hashed_item(
        dest: std::path::PathBuf,
        list_url: String,
        hash_url: String,
        mode: HostsParserMode,
    ) -> HostsDownloadItem {
        HostsDownloadItem {
            name: "hashed".to_owned(),
            urls: vec![list_url],
            hash_urls: vec![hash_url],
            dest_path: dest,
            parser_mode: mode,
        }
    }

    #[tokio::test]
    async fn matching_hash_skips_list_download() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (base, hash_hits, list_hits) = spawn_hash_and_list_server(
            format!("{hex}  hagezi-abused-tlds.txt\n"),
            b"0.0.0.0 should.not.download\n".to_vec(),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");
        tokio::fs::write(
            dir.path().join("hagezi_abused_tlds.sha256"),
            format!("{hex}\n"),
        )
        .await
        .expect("seed sidecar");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("hash check");
        assert!(!updated);
        assert_eq!(hash_hits.load(Ordering::SeqCst), 1);
        assert_eq!(list_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            tokio::fs::read_to_string(dest).await.expect("read"),
            "old.example\n"
        );
    }

    #[tokio::test]
    async fn changed_hash_downloads_the_list() {
        let list_body = b"0.0.0.0 new.example.com\n".to_vec();
        let hex = sha256_hex(&list_body);
        let (base, hash_hits, list_hits) =
            spawn_hash_and_list_server(format!("{hex}  hagezi-abused-tlds.txt\n"), list_body).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");
        tokio::fs::write(
            dir.path().join("hagezi_abused_tlds.sha256"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .await
        .expect("seed sidecar");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("download after hash change");
        assert!(updated);
        assert_eq!(hash_hits.load(Ordering::SeqCst), 1);
        assert_eq!(list_hits.load(Ordering::SeqCst), 1);
        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("new.example.com"));
    }

    /// The body arrives in many reads, with an oversized line that is skipped
    /// and no final newline. Every byte must be hashed exactly once anyway.
    #[tokio::test]
    async fn streamed_hashed_list_verifies_across_partial_reads() {
        let mut list_body = Vec::new();
        for index in 0..20_000 {
            list_body.extend_from_slice(format!("0.0.0.0 host{index}.example.com\n").as_bytes());
        }
        list_body.extend_from_slice(b"0.0.0.0 ");
        list_body.extend(std::iter::repeat_n(b'a', 70 * 1024));
        list_body.extend_from_slice(b"\n0.0.0.0 last.example.com");
        let hex = sha256_hex(&list_body);
        let (base, _, list_hits) =
            spawn_hash_and_list_server(format!("{hex}  list.txt\n"), list_body).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4 * 1024 * 1024,
            idle_timeout: Duration::from_secs(5),
        };

        assert!(download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("verified streamed download"));
        assert_eq!(list_hits.load(Ordering::SeqCst), 1);
        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert_eq!(content.lines().count(), 20_001);
        assert!(content.starts_with("host0.example.com\n"));
        assert!(content.ends_with("last.example.com\n"));
    }

    #[tokio::test]
    async fn fresh_hash_stamp_skips_network() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let (base, hash_hits, list_hits) = spawn_hash_and_list_server(
            format!("{hex}\n"),
            b"0.0.0.0 should.not.download\n".to_vec(),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");
        tokio::fs::write(
            dir.path().join("hagezi_abused_tlds.sha256"),
            format!("{hex}\n"),
        )
        .await
        .expect("seed sidecar");
        tokio::fs::write(dir.path().join("hagezi_abused_tlds.hash-checked"), "")
            .await
            .expect("seed stamp");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest,
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("stamp skip");
        assert!(!updated);
        assert_eq!(hash_hits.load(Ordering::SeqCst), 0);
        assert_eq!(list_hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn oversized_hash_file_keeps_existing_dest() {
        let (base, _, list_hits) =
            spawn_hash_and_list_server("x".repeat(8192), b"0.0.0.0 should.not.download\n".to_vec())
                .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("keep cache");
        assert!(!updated);
        assert_eq!(list_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            tokio::fs::read_to_string(dest).await.expect("read"),
            "old.example\n"
        );
    }

    #[tokio::test]
    async fn unreachable_hash_keeps_existing_dest() {
        let (base, _hash_hits, list_hits) =
            spawn_hash_and_list_server(String::new(), b"0.0.0.0 should.not.download\n".to_vec())
                .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            "http://127.0.0.1:1/hash".to_owned(),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_millis(200),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("keep cache");
        assert!(!updated);
        assert_eq!(list_hits.load(Ordering::SeqCst), 0);
        assert_eq!(
            tokio::fs::read_to_string(dest).await.expect("read"),
            "old.example\n"
        );
    }

    #[tokio::test]
    async fn unreachable_hash_without_cache_reports_hash_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("missing.txt");
        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            "http://127.0.0.1:1/list".to_owned(),
            "http://127.0.0.1:1/hash".to_owned(),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_millis(200),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("hash fetch failure must surface");
        assert!(
            matches!(
                error,
                crate::DownloadError::Http(_) | crate::DownloadError::IdleTimeout
            ),
            "expected the real hash-fetch error, got {error:?}"
        );
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn unparseable_hash_without_cache_reports_invalid_hash() {
        let (base, _, list_hits) = spawn_hash_and_list_server(
            "not a hash\n".to_owned(),
            b"0.0.0.0 should.not.download\n".to_vec(),
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("missing.txt");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("malformed hash must surface");
        assert!(matches!(error, crate::DownloadError::InvalidHashFile));
        assert_eq!(list_hits.load(Ordering::SeqCst), 0);
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn body_hash_mismatch_leaves_dest_unchanged() {
        let list_body = b"0.0.0.0 new.example.com\n".to_vec();
        let (base, _, list_hits) = spawn_hash_and_list_server(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  list.txt\n"
                .to_owned(),
            list_body,
        )
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");
        tokio::fs::write(&dest, "old.example\n")
            .await
            .expect("seed dest");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::RequireHostsAddress,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("mismatch");
        assert!(matches!(error, crate::DownloadError::HashMismatch));
        assert_eq!(list_hits.load(Ordering::SeqCst), 1);
        assert_eq!(
            tokio::fs::read_to_string(dest).await.expect("read"),
            "old.example\n"
        );
    }

    #[tokio::test]
    async fn empty_cleaned_hashed_list_fails() {
        let list_body = b"# Title only\n".to_vec();
        let hex = sha256_hex(&list_body);
        let (base, _, _) =
            spawn_hash_and_list_server(format!("{hex}  list.txt\n"), list_body).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::AllowSingleLabelNames,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let error = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect_err("empty");
        assert!(matches!(error, crate::DownloadError::EmptyList));
        assert!(!dest.exists());
    }

    #[tokio::test]
    async fn hashed_bare_tld_file_survives_clean() {
        let list_body = b"# Title: abused TLDs\nchristmas\nzip\n".to_vec();
        let hex = sha256_hex(&list_body);
        let (base, _, _) =
            spawn_hash_and_list_server(format!("{hex}  list.txt\n"), list_body).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("hagezi_abused_tlds.txt");

        let client = DownloadClient::for_local_tests();
        let download_item = hashed_item(
            dest.clone(),
            format!("{base}/list"),
            format!("{base}/hash"),
            HostsParserMode::AllowSingleLabelNames,
        );
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(5),
        };

        let updated = download_hosts_list(&client.inner, &download_item, &config)
            .await
            .expect("tld download");
        assert!(updated);
        let content = tokio::fs::read_to_string(dest).await.expect("read");
        assert!(content.contains("christmas"));
        assert!(content.contains("zip"));
        assert!(!content.contains('#'));
    }
}
