//! IANA RDAP bootstrap (`https://data.iana.org/rdap/dns.json`).

use std::collections::HashMap;

use serde::Deserialize;

use crate::error::Error;

/// HTTPS RDAP base URLs keyed by the lowercase suffix IANA published.
pub(crate) type Services = HashMap<String, String>;

#[derive(Deserialize)]
struct BootstrapFile {
    #[serde(default)]
    services: Vec<Vec<Vec<String>>>,
}

/// Parses the IANA bootstrap document into suffix → HTTPS base URL.
///
/// HTTP URLs are skipped. The first HTTPS URL for a suffix wins.
pub(crate) fn parse_bootstrap(body: &str) -> Result<Services, Error> {
    let file: BootstrapFile = serde_json::from_str(body).map_err(|_| Error::Malformed)?;
    let mut services = Services::new();
    for service in file.services {
        let (Some(suffixes), Some(urls)) = (service.first(), service.get(1)) else {
            continue;
        };
        let Some(base) = urls.iter().find(|url| url.starts_with("https://")) else {
            continue;
        };
        for suffix in suffixes {
            let suffix = suffix.trim().trim_start_matches('.').to_ascii_lowercase();
            if suffix.is_empty() {
                continue;
            }
            services.entry(suffix).or_insert_with(|| base.clone());
        }
    }
    Ok(services)
}

/// Longest published suffix of `domain`, and its RDAP base URL.
pub(crate) fn match_service<'a>(services: &'a Services, domain: &str) -> Option<&'a str> {
    let labels: Vec<&str> = domain.split('.').collect();
    (0..labels.len()).find_map(|start| {
        let suffix = labels[start..].join(".");
        services.get(&suffix).map(String::as_str)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "services": [
            [["uk"], ["https://rdap.nominet.uk/uk/"]],
            [["co.uk"], ["https://rdap.nominet.uk/co.uk/"]],
            [["com", "net"], ["http://insecure.example/", "https://rdap.verisign.com/com/v1/"]],
            [["example"], ["http://insecure.example/only"]]
        ]
    }"#;

    #[test]
    fn keeps_the_first_https_url_and_prefers_the_longest_suffix() {
        let services = parse_bootstrap(SAMPLE).unwrap();
        assert_eq!(
            match_service(&services, "example.com"),
            Some("https://rdap.verisign.com/com/v1/")
        );
        assert_eq!(
            match_service(&services, "example.co.uk"),
            Some("https://rdap.nominet.uk/co.uk/")
        );
        assert_eq!(
            match_service(&services, "www.example.net"),
            Some("https://rdap.verisign.com/com/v1/")
        );
        assert!(match_service(&services, "only.example").is_none());
    }
}
