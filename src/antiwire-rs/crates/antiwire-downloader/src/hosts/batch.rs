use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::client::DownloadClient;
use crate::hosts::download::download_hosts_list;
use crate::{DownloadConfig, DownloadError, HostsDownloadItem, HostsDownloadOutcome};

pub(crate) async fn download_hosts_batch(
    client: &DownloadClient,
    items: &[HostsDownloadItem],
    config: &DownloadConfig,
    max_parallel: usize,
) -> Vec<HostsDownloadOutcome> {
    if items.is_empty() {
        return Vec::new();
    }

    let max_parallel = max_parallel.max(1);
    let semaphore = Arc::new(Semaphore::new(max_parallel));
    let mut join_set = JoinSet::new();

    for (index, item) in items.iter().cloned().enumerate() {
        let permit = semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let http = client.inner.clone();
        let config = config.clone();

        join_set.spawn(async move {
            let _permit = permit;
            let result = download_hosts_list(&http, &item, &config).await;
            (
                index,
                HostsDownloadOutcome {
                    name: item.name,
                    result,
                },
            )
        });
    }

    let mut results: Vec<Option<HostsDownloadOutcome>> = (0..items.len()).map(|_| None).collect();
    while let Some(join_result) = join_set.join_next().await {
        match join_result {
            Ok((index, outcome)) => {
                if let Some(slot) = results.get_mut(index) {
                    *slot = Some(outcome);
                }
            }
            Err(join_err) => {
                tracing::warn!(error = %join_err, "batch download task panicked or was cancelled");
            }
        }
    }

    results
        .into_iter()
        .enumerate()
        .map(|(index, outcome)| {
            outcome.unwrap_or_else(|| {
                let name = items
                    .get(index)
                    .map_or_else(|| format!("item-{index}"), |item| item.name.clone());
                HostsDownloadOutcome {
                    name,
                    result: Err(DownloadError::Io(std::io::Error::other(
                        "download task panicked or was cancelled",
                    ))),
                }
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::download_hosts_batch;
    use crate::client::DownloadClient;
    use crate::{DownloadConfig, HostsDownloadItem};

    async fn spawn_http_server(body: Vec<u8>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0_u8; 1024];
                loop {
                    let read = socket.read(&mut buf).await.expect("read request");
                    if read == 0 || buf[..read].windows(4).any(|window| window == b"\r\n\r\n") {
                        break;
                    }
                }
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
    async fn batch_download_partial_failure() {
        let good_url = spawn_http_server(b"0.0.0.0 good.example.com\n".to_vec()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let client = DownloadClient::for_local_tests();
        let items = vec![
            HostsDownloadItem {
                name: "good".to_owned(),
                urls: vec![good_url],
                hash_urls: Vec::new(),
                dest_path: dir.path().join("good.txt"),
                parser_mode: antiwire_policy::HostsParserMode::RequireHostsAddress,
            },
            HostsDownloadItem {
                name: "bad".to_owned(),
                urls: vec!["http://127.0.0.1:1/".to_owned()],
                hash_urls: Vec::new(),
                dest_path: dir.path().join("bad.txt"),
                parser_mode: antiwire_policy::HostsParserMode::RequireHostsAddress,
            },
        ];
        let config = DownloadConfig {
            max_bytes: 4096,
            idle_timeout: Duration::from_secs(2),
        };

        let outcomes = download_hosts_batch(&client, &items, &config, 2).await;
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].result.is_ok());
        assert!(outcomes[1].result.is_err());

        let content = tokio::fs::read_to_string(dir.path().join("good.txt"))
            .await
            .expect("good file");
        assert!(content.contains("good.example.com"));
    }
}
