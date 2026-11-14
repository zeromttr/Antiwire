//! Asks IANA where a TLD's registry is, then reads that registry.

use std::time::{Duration, Instant};

use antiwire_http::{read_text_limited, HttpClient};
use tokio::sync::Mutex;

use crate::bootstrap::{self, Services};
use crate::error::Error;
use crate::name::query_names;
use crate::rdap::{self, domain_url, merge_registrar, registrar_link};
use crate::record::Registration;
use crate::whois::lookup_whois;

/// IANA RDAP bootstrap. The only directory this crate fetches.
const IANA_RDAP_BOOTSTRAP: &str = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Far above any real RDAP record or the IANA bootstrap, which are tens of KB.
/// A larger answer is refused rather than buffered.
const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

struct CachedBootstrap {
    loaded_at: Option<Instant>,
    services: Services,
}

/// Client for one process. The IANA bootstrap is cached in memory.
pub struct Lookup {
    client: HttpClient,
    bootstrap: Mutex<CachedBootstrap>,
}

impl Lookup {
    /// Builds an HTTPS client for public servers that follows at most five
    /// redirects, all on HTTPS.
    ///
    /// Registry answers name the next server to ask, so a URL here can come
    /// from a registrar's record; the client only reaches public addresses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Transport`] when the HTTP client cannot be built.
    pub fn new() -> Result<Self, Error> {
        let client = HttpClient::builder("antiwire-lookup")
            .max_redirects(5)
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(Error::from)?;
        Ok(Self {
            client,
            bootstrap: Mutex::new(CachedBootstrap {
                loaded_at: None,
                services: Services::new(),
            }),
        })
    }

    /// Registration record for `domain`.
    ///
    /// The registry RDAP server from the IANA bootstrap is asked first. A
    /// longer name the registry does not have is retried as its parent, down
    /// to two labels. When the registry links to the registrar's own RDAP
    /// record, that record is read too and adds the registrant details a thin
    /// registry leaves out; a failure there keeps the registry record. WHOIS
    /// is used when IANA lists no HTTPS RDAP service, or when the RDAP request
    /// fails before the registry answers. A registry `404` is final.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] for a name that is not a hostname,
    /// [`Error::NotFound`] when the registry has no record, [`Error::RateLimited`]
    /// when the registry asks us to slow down, [`Error::NoAuthority`] when IANA
    /// names neither protocol, and [`Error::Transport`] or [`Error::Malformed`]
    /// when the official response cannot be read.
    pub async fn lookup(&self, domain: &str) -> Result<Registration, Error> {
        self.lookup_with(domain, true).await
    }

    /// Registration record from the registry alone, without the registrar's
    /// record that [`Self::lookup`] merges in.
    ///
    /// The registry publishes the creation date, so callers that need only
    /// that skip the registrar's server, which is often slower than the
    /// registry.
    ///
    /// # Errors
    ///
    /// As [`Self::lookup`].
    pub async fn lookup_registry(&self, domain: &str) -> Result<Registration, Error> {
        self.lookup_with(domain, false).await
    }

    async fn lookup_with(
        &self,
        domain: &str,
        follow_registrar: bool,
    ) -> Result<Registration, Error> {
        let names = query_names(domain)?;
        let Some(queried) = names.first().cloned() else {
            return Err(Error::InvalidDomain);
        };
        let services = self.services().await?;
        let Some(base) = bootstrap::match_service(&services, &queried) else {
            return lookup_whois(&queried).await;
        };
        let base = base.to_owned();
        match self
            .rdap_walk(&base, &queried, &names, follow_registrar)
            .await
        {
            Ok(record) => Ok(record),
            Err(error @ (Error::NotFound(_) | Error::RateLimited | Error::Malformed)) => Err(error),
            Err(error) => match lookup_whois(&queried).await {
                Ok(record) => Ok(record),
                Err(_) => Err(error),
            },
        }
    }

    async fn services(&self) -> Result<Services, Error> {
        {
            let cached = self.bootstrap.lock().await;
            let fresh = cached
                .loaded_at
                .is_some_and(|loaded| loaded.elapsed() < BOOTSTRAP_TTL);
            if fresh {
                return Ok(cached.services.clone());
            }
        }
        let body = self.fetch_text(IANA_RDAP_BOOTSTRAP).await?;
        let services = bootstrap::parse_bootstrap(&body)?;
        let mut cached = self.bootstrap.lock().await;
        cached.loaded_at = Some(Instant::now());
        cached.services.clone_from(&services);
        Ok(services)
    }

    async fn rdap_walk(
        &self,
        base: &str,
        queried: &str,
        names: &[String],
        follow_registrar: bool,
    ) -> Result<Registration, Error> {
        let mut last = queried.to_owned();
        for name in names {
            last.clone_from(name);
            let url = domain_url(base, name);
            match self.fetch_rdap(&url).await {
                Ok(body) => match rdap::parse_rdap(&body, queried, &url) {
                    Err(Error::NotFound(_)) => {}
                    Ok(record) if follow_registrar => {
                        return Ok(self.with_registrar(record, &body).await)
                    }
                    Ok(record) => return Ok(record),
                    Err(error) => return Err(error),
                },
                Err(Error::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Err(Error::NotFound(last))
    }

    /// Merges the registrar's RDAP record when the registry links one and it
    /// describes the same domain.
    async fn with_registrar(&self, registry: Registration, registry_body: &str) -> Registration {
        let Some(url) = registrar_link(registry_body) else {
            return registry;
        };
        if registry.registry_source.as_deref() == Some(url.as_str()) {
            return registry;
        }
        let Ok(body) = self.fetch_rdap(&url).await else {
            return registry;
        };
        match rdap::parse_rdap(&body, &registry.queried, &url) {
            Ok(registrar) if registrar.domain.eq_ignore_ascii_case(&registry.domain) => {
                merge_registrar(registry, registrar)
            }
            _ => registry,
        }
    }

    async fn fetch_rdap(&self, url: &str) -> Result<String, Error> {
        let response = self
            .client
            .get(url)
            .map_err(Error::from)?
            .header(
                antiwire_http::reqwest::header::ACCEPT,
                "application/rdap+json",
            )
            .send()
            .await
            .map_err(|error| Error::Transport(error.to_string()))?;
        let status = response.status();
        if status.as_u16() == 429 {
            return Err(Error::RateLimited);
        }
        if status.as_u16() == 404 {
            return Err(Error::NotFound(url.to_owned()));
        }
        if !status.is_success() {
            return Err(Error::Transport(format!("RDAP {status} for {url}")));
        }
        read_text_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(Error::from)
    }

    async fn fetch_text(&self, url: &str) -> Result<String, Error> {
        let response = self
            .client
            .get(url)
            .map_err(Error::from)?
            .header(antiwire_http::reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| Error::Transport(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Transport(format!("bootstrap {status}")));
        }
        read_text_limited(response, MAX_RESPONSE_BYTES)
            .await
            .map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "queries IANA and the .com registry"]
    async fn example_com_comes_from_the_com_registry() {
        let lookup = Lookup::new().unwrap();
        let record = lookup.lookup("example.com").await.unwrap();
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.source, crate::Source::Rdap);
        assert_eq!(record.registrar_id.as_deref(), Some("376"));
        assert_eq!(
            record.registered_at.unwrap().date().to_string(),
            "1995-08-14"
        );
        assert!(record.dnssec.unwrap());
    }

    #[tokio::test]
    #[ignore = "queries IANA, the .com registry and the registrar it links"]
    async fn a_thin_registry_record_is_completed_by_the_registrar() {
        let lookup = Lookup::new().unwrap();
        let record = lookup.lookup("google.com").await.unwrap();
        assert!(
            record.registrar_source.is_some(),
            "registrar RDAP not merged"
        );
        assert_eq!(
            record.registrant_organization.as_deref(),
            Some("Google LLC")
        );
        assert_eq!(record.registrant_country.as_deref(), Some("US"));
        assert!(record.handle.is_some());
        assert!(record.abuse_email.is_some());
        assert!(record.whois_server.is_some());
        println!("{record:#?}");
    }

    /// Diagnostic: prints how long each lookup takes with and without the
    /// registrar's record. Asserts nothing.
    #[tokio::test]
    #[ignore = "queries IANA, registries and registrars; prints timings"]
    async fn probe_registrar_follow_up_cost() {
        let lookup = Lookup::new().unwrap();
        lookup.lookup_registry("example.com").await.unwrap();
        for domain in [
            "google.com",
            "github.com",
            "reddit.com",
            "cloudflare.com",
            "amazon.com",
            "netflix.com",
            "stackoverflow.com",
            "tiktok.com",
            "zoom.us",
            "wikipedia.org",
        ] {
            let start = Instant::now();
            let full = lookup.lookup(domain).await;
            let full_ms = start.elapsed().as_millis();
            let start = Instant::now();
            let registry = lookup.lookup_registry(domain).await;
            let registry_ms = start.elapsed().as_millis();
            let same_date =
                matches!((&full, &registry), (Ok(a), Ok(b)) if a.registered_at == b.registered_at);
            println!(
                "{domain}: full={full_ms}ms registry_only={registry_ms}ms same_date={same_date}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "queries IANA and the .com registry"]
    async fn the_registry_alone_dates_a_thin_record() {
        let lookup = Lookup::new().unwrap();
        let record = lookup.lookup_registry("google.com").await.unwrap();
        assert!(record.registrar_source.is_none(), "registrar was fetched");
        assert_eq!(
            record.registered_at.unwrap().date().to_string(),
            "1997-09-15"
        );
    }
}
