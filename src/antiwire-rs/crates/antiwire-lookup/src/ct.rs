//! Certificate Transparency search through crt.sh.
//!
//! Every publicly trusted TLS certificate is published in CT logs (RFC 9162),
//! so the names on them are the most complete public list of a domain's
//! hostnames. The logs cannot be searched by name directly; crt.sh (run by
//! Sectigo) indexes them. It is a third party: unlike the registration
//! lookups, this sends the domain to crt.sh, and callers must only run it on
//! an explicit request.

use std::collections::BTreeMap;
use std::time::Duration;

use antiwire_http::HttpClient;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::error::Error;
use crate::name::query_names;
use crate::rdap::parse_time;

const CRT_SH: &str = "https://crt.sh/";
/// crt.sh answers slowly even for small domains.
const SEARCH_TIMEOUT: Duration = Duration::from_secs(90);
/// Larger responses are cut off and reported as truncated.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;
/// Names kept after aggregation.
const MAX_NAMES: usize = 1000;

/// One hostname seen on certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateName {
    /// Lowercase hostname; wildcard names keep their `*.` label.
    pub name: String,
    /// Certificates listing this name.
    pub certificates: u32,
    /// Earliest `notBefore` among them.
    pub first_issued: Option<OffsetDateTime>,
    /// Latest `notAfter` among them.
    pub latest_expiry: Option<OffsetDateTime>,
    /// Issuing CA's common name on the certificate that expires last.
    pub issuer: Option<String>,
}

/// Names under one domain found in CT logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateSearchResult {
    pub domain: String,
    /// Certificates crt.sh returned.
    pub certificates: u32,
    /// Busiest-validity first: names with a certificate still valid, then by
    /// latest expiry.
    pub names: Vec<CertificateName>,
    /// The response or the name list hit a size limit.
    pub truncated: bool,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    name_value: String,
    #[serde(default)]
    issuer_name: String,
    #[serde(default)]
    not_before: String,
    #[serde(default)]
    not_after: String,
}

/// Client for crt.sh searches.
pub struct CertificateSearch {
    client: HttpClient,
}

impl CertificateSearch {
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when the HTTP client cannot be built.
    pub fn new() -> Result<Self, Error> {
        let client = HttpClient::builder("antiwire-lookup")
            .max_redirects(5)
            .connect_timeout(Duration::from_secs(10))
            .timeout(SEARCH_TIMEOUT)
            .build()
            .map_err(|error| Error::Transport(error.to_string()))?;
        Ok(Self { client })
    }

    /// Hostnames at or under `domain` on logged certificates, expired ones included.
    ///
    /// Pass the registered domain (`example.co.uk`), not a guess at it: the
    /// search covers exactly the name given and everything beneath it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] for a name that is not a hostname,
    /// [`Error::RateLimited`] when crt.sh asks us to slow down, and
    /// [`Error::Transport`] or [`Error::Malformed`] when its answer cannot
    /// be read. crt.sh times out on very large domains; that is a transport error.
    pub async fn search(&self, domain: &str) -> Result<CertificateSearchResult, Error> {
        let domain = query_names(domain)?
            .into_iter()
            .next()
            .ok_or(Error::InvalidDomain)?;
        let response = self
            .client
            .get(CRT_SH)
            .map_err(|error| Error::Transport(error.to_string()))?
            .query(&[
                ("q", format!("%.{domain}").as_str()),
                ("output", "json"),
                ("deduplicate", "Y"),
            ])
            .send()
            .await
            .map_err(|error| Error::Transport(error.to_string()))?;
        let status = response.status();
        if status.as_u16() == 429 {
            return Err(Error::RateLimited);
        }
        if !status.is_success() {
            return Err(Error::Transport(format!("crt.sh answered {status}")));
        }
        let (body, cut) = read_capped(response).await?;
        let entries = if cut {
            parse_partial(&body)
        } else {
            serde_json::from_slice::<Vec<Entry>>(&body).map_err(|_| Error::Malformed)?
        };
        Ok(aggregate(&domain, &entries, cut, OffsetDateTime::now_utc()))
    }
}

async fn read_capped(mut response: antiwire_http::HttpResponse) -> Result<(Vec<u8>, bool), Error> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| Error::Transport(error.to_string()))?
    {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Ok((body, true));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, false))
}

/// The complete entries at the start of a cut-off JSON array.
fn parse_partial(body: &[u8]) -> Vec<Entry> {
    let text = String::from_utf8_lossy(body);
    let Some(end) = text.rfind("},") else {
        return Vec::new();
    };
    serde_json::from_str(&format!("{}}}]", &text[..end])).unwrap_or_default()
}

fn issuer_common_name(issuer: &str) -> Option<String> {
    issuer
        .split(", ")
        .find_map(|part| part.strip_prefix("CN="))
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
}

fn crt_time(text: &str) -> Option<OffsetDateTime> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    // crt.sh prints UTC without an offset.
    parse_time(&format!("{text}Z")).or_else(|| parse_time(text))
}

fn aggregate(
    domain: &str,
    entries: &[Entry],
    truncated: bool,
    now: OffsetDateTime,
) -> CertificateSearchResult {
    let suffix = format!(".{domain}");
    let mut by_name: BTreeMap<String, CertificateName> = BTreeMap::new();
    for entry in entries {
        let valid_from = crt_time(&entry.not_before);
        let expires = crt_time(&entry.not_after);
        let ca = issuer_common_name(&entry.issuer_name);
        for raw in entry.name_value.split('\n') {
            let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if name.contains('@') || !(name == domain || name.ends_with(&suffix)) {
                continue;
            }
            let item = by_name
                .entry(name.clone())
                .or_insert_with(|| CertificateName {
                    name,
                    certificates: 0,
                    first_issued: None,
                    latest_expiry: None,
                    issuer: None,
                });
            item.certificates = item.certificates.saturating_add(1);
            if valid_from.is_some_and(|at| item.first_issued.is_none_or(|first| at < first)) {
                item.first_issued = valid_from;
            }
            if expires.is_some_and(|at| item.latest_expiry.is_none_or(|latest| at > latest)) {
                item.latest_expiry = expires;
                item.issuer.clone_from(&ca);
            }
        }
    }
    let mut names: Vec<CertificateName> = by_name.into_values().collect();
    names.sort_by(|a, b| {
        let valid = |item: &CertificateName| item.latest_expiry.is_some_and(|at| at > now);
        valid(b)
            .cmp(&valid(a))
            .then(b.latest_expiry.cmp(&a.latest_expiry))
            .then(a.name.cmp(&b.name))
    });
    let cut = names.len() > MAX_NAMES;
    names.truncate(MAX_NAMES);
    CertificateSearchResult {
        domain: domain.to_owned(),
        certificates: u32::try_from(entries.len()).unwrap_or(u32::MAX),
        names,
        truncated: truncated || cut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month};

    fn utc(year: i32, month: Month, day: u8) -> OffsetDateTime {
        Date::from_calendar_date(year, month, day)
            .unwrap()
            .midnight()
            .assume_utc()
    }

    const SAMPLE: &str = r#"[
        {"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "name_value": "api.example.com\nexample.com",
         "not_before": "2026-08-01T00:00:00", "not_after": "2026-10-30T00:00:00"},
        {"issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
         "name_value": "api.example.com\n*.example.com\nadmin@example.com\nexample.org",
         "not_before": "2020-01-01T00:00:00", "not_after": "2021-01-01T00:00:00"},
        {"issuer_name": "C=US, O=Let's Encrypt, CN=E6", "name_value": "old.example.com",
         "not_before": "2019-01-01T00:00:00", "not_after": "2019-04-01T00:00:00"}
    ]"#;

    #[test]
    fn aggregates_names_under_the_domain() {
        let entries: Vec<Entry> = serde_json::from_str(SAMPLE).unwrap();
        let now = utc(2026, Month::September, 28);
        let result = aggregate("example.com", &entries, false, now);
        let names: Vec<&str> = result.names.iter().map(|item| item.name.as_str()).collect();
        // Still-valid names first, then by latest expiry.
        assert_eq!(
            names,
            [
                "api.example.com",
                "example.com",
                "*.example.com",
                "old.example.com"
            ]
        );
        let api = &result.names[0];
        assert_eq!(api.certificates, 2);
        assert_eq!(api.first_issued, Some(utc(2020, Month::January, 1)));
        assert_eq!(api.latest_expiry, Some(utc(2026, Month::October, 30)));
        assert_eq!(api.issuer.as_deref(), Some("R11"));
        assert_eq!(result.certificates, 3);
        assert!(!result.truncated);
    }

    #[test]
    fn keeps_the_complete_entries_of_a_cut_off_response() {
        let cut = &SAMPLE[..SAMPLE.find("old.example.com").unwrap()];
        let entries = parse_partial(cut.as_bytes());
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    #[ignore = "queries crt.sh, which can take a minute"]
    async fn iana_org_names_come_from_ct_logs() {
        let search = CertificateSearch::new().unwrap();
        let result = search.search("iana.org").await.unwrap();
        assert_eq!(result.domain, "iana.org");
        assert!(result.names.iter().any(|item| item.name == "data.iana.org"));
        println!(
            "{} names from {} certificates",
            result.names.len(),
            result.certificates
        );
    }
}
