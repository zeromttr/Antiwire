use std::fs::File;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use directories::ProjectDirs;
use maxminddb::{geoip2, Reader};
use thiserror::Error;

// Allows the City database with ample room for growth, while bounding each load.
const MAX_DATABASE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum GeoError {
    #[error("geoip data not loaded")]
    NotLoaded,
}

#[derive(Debug, Clone, Default)]
pub struct GeoResult {
    pub country_code: String,
    pub isp: String,
}

/// `GeoIP` lookup via `MaxMind` `GeoLite2` databases on disk.
pub struct GeoIpLookup {
    country: Option<Reader<Vec<u8>>>,
    asn: Option<Reader<Vec<u8>>>,
    city: Option<Reader<Vec<u8>>>,
}

impl Default for GeoIpLookup {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpLookup {
    pub fn new() -> Self {
        Self {
            country: None,
            asn: None,
            city: None,
        }
    }

    /// Auto-discovers `GeoLite2` databases from common install paths.
    pub fn with_auto_discovery() -> Self {
        let mut country_path = None;
        let mut asn_path = None;
        let mut city_path = None;

        for base_path in search_paths() {
            if country_path.is_none() {
                let path = base_path.join("GeoLite2-Country.mmdb");
                if path.is_file() {
                    country_path = Some(path);
                }
            }

            if asn_path.is_none() {
                let path = base_path.join("GeoLite2-ASN.mmdb");
                if path.is_file() {
                    asn_path = Some(path);
                }
            }

            if city_path.is_none() {
                let path = base_path.join("GeoLite2-City.mmdb");
                if path.is_file() {
                    city_path = Some(path);
                }
            }

            if country_path.is_some() && asn_path.is_some() && city_path.is_some() {
                break;
            }
        }

        Self::from_paths(country_path, asn_path, city_path)
    }

    /// Prefers the daemon's managed geoip directory (where `GeoDatabaseService`
    /// writes downloaded databases); falls back to [`Self::with_auto_discovery`]'s
    /// search paths so manually-installed system-wide mmdb files still work.
    pub fn with_data_dir(data_dir: impl AsRef<std::path::Path>) -> Self {
        let data_dir = data_dir.as_ref();
        let country = data_dir.join("GeoLite2-Country.mmdb");
        let asn = data_dir.join("GeoLite2-ASN.mmdb");
        let city = data_dir.join("GeoLite2-City.mmdb");

        if country.is_file() || asn.is_file() || city.is_file() {
            return Self::from_paths(
                country.is_file().then_some(country),
                asn.is_file().then_some(asn),
                city.is_file().then_some(city),
            );
        }

        Self::with_auto_discovery()
    }

    pub fn from_paths(
        country_path: Option<PathBuf>,
        asn_path: Option<PathBuf>,
        city_path: Option<PathBuf>,
    ) -> Self {
        Self {
            country: open_reader(country_path),
            asn: open_reader(asn_path),
            city: open_reader(city_path),
        }
    }

    pub fn is_loaded(&self) -> bool {
        self.country.is_some() || self.asn.is_some() || self.city.is_some()
    }

    /// Looks up the country and the network operator of `ip`. A private or local address
    /// gets an empty result.
    ///
    /// # Errors
    ///
    /// [`GeoError::NotLoaded`] when no database is loaded.
    pub fn lookup(&self, ip: IpAddr) -> Result<GeoResult, GeoError> {
        if !self.is_loaded() {
            return Err(GeoError::NotLoaded);
        }

        if is_private_or_local(&ip) {
            return Ok(GeoResult::default());
        }

        let mut country_code = String::new();
        let mut isp = String::new();

        if let Some(reader) = &self.country {
            if let Ok(Some(country)) = reader
                .lookup(ip)
                .and_then(|r| r.decode::<geoip2::Country>())
            {
                country_code = country.country.iso_code.unwrap_or_default().to_string();
            }
        }

        if let Some(reader) = &self.asn {
            if let Ok(Some(asn)) = reader.lookup(ip).and_then(|r| r.decode::<geoip2::Asn>()) {
                isp = asn
                    .autonomous_system_organization
                    .unwrap_or_default()
                    .to_string();
            }
        }

        if let Some(reader) = &self.city {
            if let Ok(Some(city)) = reader.lookup(ip).and_then(|r| r.decode::<geoip2::City>()) {
                if country_code.is_empty() {
                    country_code = city.country.iso_code.unwrap_or_default().to_string();
                }
            }
        }

        Ok(GeoResult { country_code, isp })
    }
}

fn open_reader(path: Option<PathBuf>) -> Option<Reader<Vec<u8>>> {
    path.and_then(|path| read_database(&path, MAX_DATABASE_BYTES).ok())
        .and_then(|bytes| Reader::from_source(bytes).ok())
}

fn read_database(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(io::Error::other(
            "GeoIP database is not a regular file within the size limit",
        ));
    }
    // Also bound the read: the file may grow after metadata was obtained.
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(io::Error::other("GeoIP database exceeds the size limit"));
    }
    Ok(bytes)
}

fn search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(directories) = ProjectDirs::from("com", "Antiwire", "Antiwire") {
        paths.push(directories.data_local_dir().join("geoip"));
    }

    paths.push(PathBuf::from("/usr/share/GeoIP"));
    paths.push(PathBuf::from("/usr/local/share/GeoIP"));
    paths.push(PathBuf::from("/opt/homebrew/share/GeoIP"));
    paths.push(PathBuf::from("/var/lib/GeoIP"));

    if let Some(program_data) = std::env::var_os("ProgramData") {
        paths.push(PathBuf::from(program_data).join("GeoIP"));
    }

    // Never resolve database names relative to the daemon's working directory.
    paths.retain(|path| path.is_absolute());
    paths
}

fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || ((v6.segments()[0] & 0xffc0) == 0xfe80)
                || ((v6.segments()[0] & 0xfe00) == 0xfc00)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_uses_only_absolute_paths() {
        assert!(search_paths().iter().all(|path| path.is_absolute()));
    }

    #[test]
    fn database_reads_are_limited() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("database.mmdb");
        std::fs::write(&path, b"12345").unwrap();
        assert_eq!(read_database(&path, 5).unwrap(), b"12345");
        assert!(read_database(&path, 4).is_err());
        assert!(read_database(dir.path(), 100).is_err());
    }

    #[test]
    fn empty_resolver_is_not_loaded() {
        let geo = GeoIpLookup::new();
        assert!(!geo.is_loaded());
        assert!(geo.lookup("127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn auto_discovery_lookup_when_available() {
        let geo = GeoIpLookup::with_auto_discovery();
        if !geo.is_loaded() {
            return;
        }

        let result = geo.lookup("1.1.1.1".parse().unwrap()).expect("lookup");
        assert_ne!(result.country_code, "");
    }

    #[test]
    fn from_paths_opens_existing_files() {
        for base in search_paths() {
            if !base.is_dir() {
                continue;
            }

            let country = base.join("GeoLite2-Country.mmdb");
            if !country.is_file() {
                continue;
            }

            let geo = GeoIpLookup::from_paths(Some(country), None, None);
            assert!(geo.is_loaded());
            return;
        }
    }
}
