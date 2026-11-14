//! Where the GeoLite2-City database comes from.

use std::path::Path;

use antiwire_downloader::{DownloadClient, DownloadConfig};
use serde::Deserialize;
use tracing::info;

/// The gzip archive name the publisher uses.
pub(super) const CITY_GZ_FILENAME: &str = "GeoLite2-City.mmdb.gz";

/// Downloads the latest GeoLite2-City database.
#[async_trait::async_trait]
pub trait GeoDatabaseSource: Send + Sync {
    /// Writes the latest gzip-compressed database to `dest`, verified
    /// against the digest its publisher lists. Returns the version.
    async fn download_latest(&self, dest: &Path) -> Result<String, String>;
}

/// Downloads from jsDelivr's mirror of the `geolite2-city` npm package,
/// pinned to the version it reports as latest.
pub struct JsDelivrGeoSource {
    client: DownloadClient,
}

impl JsDelivrGeoSource {
    /// # Panics
    ///
    /// Panics if the TLS backend cannot be initialized.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: DownloadClient::public_only(),
        }
    }
}

impl Default for JsDelivrGeoSource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl GeoDatabaseSource for JsDelivrGeoSource {
    async fn download_latest(&self, dest: &Path) -> Result<String, String> {
        let release = resolve_release(&self.client).await?;
        let url = format!(
            "{}@{}/{CITY_GZ_FILENAME}",
            antiwire_tuning::GEOLITE2_CITY_CDN,
            release.version
        );
        info!(%url, version = %release.version, "downloading GeoLite2-City database");
        let config = DownloadConfig {
            // The published size is exact, so nothing larger is accepted.
            max_bytes: release.size,
            idle_timeout: antiwire_tuning::GEOIP_DOWNLOAD_IDLE_TIMEOUT,
        };
        self.client
            .download_verified_file(&url, dest, &config, &release.sha256)
            .await
            .map_err(|error| error.to_string())?;
        Ok(release.version)
    }
}

/// One published release of the database, as jsDelivr describes it.
#[derive(Debug, PartialEq, Eq)]
struct GeoRelease {
    version: String,
    sha256: [u8; 32],
    size: u64,
}

#[derive(Deserialize)]
struct ResolvedVersion {
    version: Option<String>,
}

#[derive(Deserialize)]
struct ReleaseListing {
    files: Vec<ListedFile>,
}

#[derive(Deserialize)]
struct ListedFile {
    name: String,
    /// Base64 SHA-256 of the file.
    hash: String,
    size: u64,
}

/// Finds the latest release and the digest jsDelivr publishes for its database
/// file. The download is then pinned to that version, so the digest describes
/// exactly the file fetched, even if a new version is published meanwhile.
async fn resolve_release(client: &DownloadClient) -> Result<GeoRelease, String> {
    let config = DownloadConfig {
        max_bytes: antiwire_tuning::GEOIP_MAX_METADATA_BYTES,
        idle_timeout: antiwire_tuning::GEOIP_DOWNLOAD_IDLE_TIMEOUT,
    };
    let api = antiwire_tuning::GEOLITE2_CITY_PACKAGE_API;
    let resolved = client
        .fetch_bytes(&format!("{api}/resolved"), &config)
        .await
        .map_err(|error| format!("GeoLite2-City version lookup failed: {error}"))?;
    let version = parse_resolved_version(&resolved)?;
    let listing = client
        .fetch_bytes(&format!("{api}@{version}?structure=flat"), &config)
        .await
        .map_err(|error| format!("GeoLite2-City checksum lookup failed: {error}"))?;
    parse_release_listing(&listing, version)
}

fn parse_resolved_version(body: &[u8]) -> Result<String, String> {
    let resolved: ResolvedVersion = serde_json::from_slice(body)
        .map_err(|error| format!("GeoLite2-City version response is malformed: {error}"))?;
    let version = resolved
        .version
        .ok_or("GeoLite2-City has no published version")?;
    // The version is placed in URL paths, so accept only version characters.
    let valid = !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'));
    if !valid {
        return Err(format!("GeoLite2-City version {version:?} is not valid"));
    }
    Ok(version)
}

fn parse_release_listing(body: &[u8], version: String) -> Result<GeoRelease, String> {
    let listing: ReleaseListing = serde_json::from_slice(body)
        .map_err(|error| format!("GeoLite2-City checksum response is malformed: {error}"))?;
    let file_name = format!("/{CITY_GZ_FILENAME}");
    let file = listing
        .files
        .into_iter()
        .find(|file| file.name == file_name)
        .ok_or_else(|| format!("GeoLite2-City {version} does not list {CITY_GZ_FILENAME}"))?;
    let sha256 = data_encoding::BASE64
        .decode(file.hash.as_bytes())
        .ok()
        .and_then(|digest| <[u8; 32]>::try_from(digest).ok())
        .ok_or_else(|| format!("GeoLite2-City {version} lists an invalid checksum"))?;
    if file.size == 0 || file.size > antiwire_tuning::GEOIP_MAX_COMPRESSED_DOWNLOAD_BYTES {
        return Err(format!(
            "GeoLite2-City {version} lists an unexpected size of {} bytes",
            file.size
        ));
    }
    Ok(GeoRelease {
        version,
        sha256,
        size: file.size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trimmed from jsDelivr's real responses for version 1.0.108.
    const RESOLVED: &str = r#"{"type":"npm","name":"geolite2-city","version":"1.0.108"}"#;
    const LISTING: &str = r#"{
        "type": "npm", "name": "geolite2-city", "version": "1.0.108", "default": null,
        "files": [
            {"name": "/GeoLite2-City.mmdb.gz",
             "hash": "gUd/wGpBEJrqKiv0vS9tTgSfflQ9KdpwtjoqS6MYcK8=", "size": 26451474},
            {"name": "/package.json",
             "hash": "TJWuTurqcHO9cAuUm7hu4F3ZXgHVJW1TFYsEhLLq9mg=", "size": 619}
        ]
    }"#;

    #[test]
    fn release_metadata_yields_the_pinned_version_digest_and_size() {
        let version = parse_resolved_version(RESOLVED.as_bytes()).expect("version");
        let release = parse_release_listing(LISTING.as_bytes(), version).expect("release");
        assert_eq!(release.version, "1.0.108");
        assert_eq!(release.size, 26_451_474);
        assert_eq!(
            data_encoding::HEXLOWER.encode(&release.sha256),
            "81477fc06a41109aea2a2bf4bd2f6d4e049f7e543d29da70b63a2a4ba31870af"
        );
    }

    #[test]
    fn versions_that_could_alter_the_url_are_rejected() {
        for version in ["", "1.0/../../x", "1.0?x=1", "1.0#x", "latest version"] {
            let body = serde_json::json!({ "version": version }).to_string();
            assert!(
                parse_resolved_version(body.as_bytes()).is_err(),
                "{version:?}"
            );
        }
        assert!(parse_resolved_version(br#"{"version":null}"#).is_err());
        assert!(parse_resolved_version(b"not json").is_err());
    }

    #[test]
    fn listings_without_a_usable_database_entry_are_rejected() {
        let missing = r#"{"files":[{"name":"/package.json","hash":"AA==","size":1}]}"#;
        let short_hash = r#"{"files":[{"name":"/GeoLite2-City.mmdb.gz","hash":"AA==","size":1}]}"#;
        let empty = r#"{"files":[{"name":"/GeoLite2-City.mmdb.gz",
            "hash":"gUd/wGpBEJrqKiv0vS9tTgSfflQ9KdpwtjoqS6MYcK8=","size":0}]}"#;
        let oversized = format!(
            r#"{{"files":[{{"name":"/GeoLite2-City.mmdb.gz",
            "hash":"gUd/wGpBEJrqKiv0vS9tTgSfflQ9KdpwtjoqS6MYcK8=","size":{}}}]}}"#,
            antiwire_tuning::GEOIP_MAX_COMPRESSED_DOWNLOAD_BYTES + 1
        );
        for body in [missing, short_hash, empty, oversized.as_str()] {
            assert!(
                parse_release_listing(body.as_bytes(), "1.0.108".to_owned()).is_err(),
                "{body}"
            );
        }
    }
}
