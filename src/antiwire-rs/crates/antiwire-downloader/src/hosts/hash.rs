use std::path::{Path, PathBuf};
use std::time::Duration;

use data_encoding::HEXLOWER;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::error::{map_stream_io_error, DownloadError};
use crate::response::{limited_body, send};
use crate::DownloadConfig;

const HASH_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const HASH_MAX_BYTES: u64 = 4096;

pub(crate) fn parse_hash_file(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let token = line.split_whitespace().next()?.to_ascii_lowercase();
        if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(token);
        }
    }
    None
}

#[cfg(test)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(Sha256::new_with_prefix(bytes))
}

/// Lowercase hex of a finished SHA-256, the form hash files publish.
pub(crate) fn hex_digest(hasher: Sha256) -> String {
    HEXLOWER.encode(&hasher.finalize())
}

pub(crate) fn sidecar_path(dest: &Path) -> PathBuf {
    dest.with_file_name(format!(
        "{}.sha256",
        dest.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("list")
    ))
}

pub(crate) fn stamp_path(dest: &Path) -> PathBuf {
    dest.with_file_name(format!(
        "{}.hash-checked",
        dest.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("list")
    ))
}

pub(crate) fn stamp_is_fresh(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified
        .elapsed()
        .is_ok_and(|age| age < HASH_CHECK_INTERVAL)
}

/// True when a hashed list should hit the network (missing dest, stale stamp, or no sidecar).
#[must_use]
pub fn hashed_cache_needs_revalidation(dest: &Path, hash_urls: &[String]) -> bool {
    if hash_urls.is_empty() {
        return false;
    }
    if !dest.exists() {
        return true;
    }
    if !stamp_is_fresh(&stamp_path(dest)) {
        return true;
    }
    std::fs::read_to_string(sidecar_path(dest))
        .ok()
        .and_then(|text| parse_hash_file(&text))
        .is_none()
}

pub(crate) fn list_url_for_hash<'a>(hash_url: &str, list_urls: &'a [String]) -> Option<&'a str> {
    let host = url_host(hash_url)?;
    list_urls
        .iter()
        .map(String::as_str)
        .find(|url| url_host(url) == Some(host))
}

fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let hostport = rest.split(['/', '?', '#']).next()?;
    let host = hostport.rsplit('@').next()?;
    if host.starts_with('[') {
        return host
            .split(']')
            .next()
            .map(|value| value.trim_start_matches('['));
    }
    host.split(':').next()
}

pub(crate) async fn fetch_remote_hash(
    client: &antiwire_http::HttpClient,
    url: &str,
    config: &DownloadConfig,
) -> Result<String, DownloadError> {
    let bytes = fetch_limited_bytes(client, url, config, HASH_MAX_BYTES).await?;
    parse_hash_file(&String::from_utf8_lossy(&bytes)).ok_or(DownloadError::InvalidHashFile)
}

pub(crate) async fn fetch_limited_bytes(
    client: &antiwire_http::HttpClient,
    url: &str,
    config: &DownloadConfig,
    max_bytes: u64,
) -> Result<Vec<u8>, DownloadError> {
    let response = send(client.get(url)?, config).await?;
    let mut reader = BufReader::new(limited_body(response, max_bytes));
    let mut out = Vec::new();
    loop {
        let available = match tokio::time::timeout(config.idle_timeout, reader.fill_buf()).await {
            Ok(Ok(buf)) => buf,
            Ok(Err(error)) => {
                let limit_exceeded = reader.get_ref().limit_exceeded();
                return Err(map_stream_io_error(error, limit_exceeded, max_bytes));
            }
            Err(_) => return Err(DownloadError::IdleTimeout),
        };
        if available.is_empty() {
            break;
        }
        let consume = available.len();
        out.extend_from_slice(available);
        reader.consume(consume);
    }
    Ok(out)
}

pub(crate) async fn write_text_file(path: &Path, body: &str) -> Result<(), DownloadError> {
    tokio::fs::write(path, body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        hashed_cache_needs_revalidation, list_url_for_hash, parse_hash_file, sha256_hex,
        sidecar_path, stamp_path,
    };

    #[test]
    fn parse_hash_file_reads_sha256sum_format() {
        assert_eq!(
            parse_hash_file(
                "# note\nabc\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  hagezi-abused-tlds.txt\n"
            )
            .as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(parse_hash_file("not-a-hash"), None);
    }

    #[test]
    fn pairs_hash_and_list_from_the_same_host() {
        let lists = [
            "https://cdn.jsdelivr.net/gh/antiwire/antiwire@main/data/list.txt".to_owned(),
            "https://raw.githubusercontent.com/antiwire/antiwire/main/data/list.txt".to_owned(),
        ];
        assert_eq!(
            list_url_for_hash(
                "https://cdn.jsdelivr.net/gh/antiwire/antiwire@main/data/list.sha256",
                &lists
            ),
            Some(lists[0].as_str())
        );
        assert_eq!(
            list_url_for_hash(
                "https://raw.githubusercontent.com/antiwire/antiwire/main/data/list.sha256",
                &lists
            ),
            Some(lists[1].as_str())
        );
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn hashed_cache_revalidation_uses_dest_stamp_and_sidecar() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let dir = tempfile::tempdir().expect("tempdir");
        let dest = dir.path().join("list.txt");
        let hash_urls = vec!["https://example.test/list.sha256".to_owned()];

        assert!(!hashed_cache_needs_revalidation(&dest, &[]));
        assert!(hashed_cache_needs_revalidation(&dest, &hash_urls));

        std::fs::write(&dest, "christmas\n").expect("dest");
        assert!(hashed_cache_needs_revalidation(&dest, &hash_urls));

        std::fs::write(sidecar_path(&dest), format!("{hex}  list.txt\n")).expect("sidecar");
        assert!(hashed_cache_needs_revalidation(&dest, &hash_urls));

        std::fs::write(stamp_path(&dest), "").expect("stamp");
        assert!(!hashed_cache_needs_revalidation(&dest, &hash_urls));
    }
}
