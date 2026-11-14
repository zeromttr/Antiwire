//! WHOIS (RFC 3912) against the server IANA refers, then one registrar referral.

use std::time::Duration;

use antiwire_http::Destinations;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::Error;
use crate::rdap::{is_redacted, parse_time, published, web_url};
use crate::record::{Registration, Source};

const IANA_WHOIS: &str = "whois.iana.org";
const WHOIS_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_WHOIS_BYTES: u64 = 64 * 1024;

/// Reads a registration from WHOIS when the TLD has no HTTPS RDAP service,
/// and when an RDAP request fails before the registry answers.
pub(crate) async fn lookup_whois(domain: &str) -> Result<Registration, Error> {
    let tld = domain.rsplit('.').next().ok_or(Error::InvalidDomain)?;
    let referral = query(IANA_WHOIS, tld).await?;
    let server = referred_server(&referral).ok_or_else(|| Error::NoAuthority(tld.to_owned()))?;
    let registry_text = query(&server, domain).await?;
    if not_found(&registry_text) {
        return Err(Error::NotFound(domain.to_owned()));
    }
    let mut registry = parse_whois(&registry_text, domain)?;
    registry.registry_source = Some(server.clone());
    let Some(registrar_host) = registrar_server(&registry_text) else {
        return Ok(registry);
    };
    if registrar_host.eq_ignore_ascii_case(&server) {
        return Ok(registry);
    }
    let Ok(registrar_text) = query(&registrar_host, domain).await else {
        return Ok(registry);
    };
    if not_found(&registrar_text) {
        return Ok(registry);
    }
    let Some(referred_domain) = published_domain(&registrar_text) else {
        return Ok(registry);
    };
    if !referred_domain.eq_ignore_ascii_case(domain) {
        return Ok(registry);
    }
    let Ok(mut registrar) = parse_whois(&registrar_text, domain) else {
        return Ok(registry);
    };
    registrar.registry_source = Some(registrar_host);
    Ok(merge(registry, registrar))
}

async fn query(host: &str, question: &str) -> Result<String, Error> {
    if !valid_host(host) {
        return Err(Error::Transport(format!("refused WHOIS host {host}")));
    }
    let connect = connect_public(host);
    let mut stream = tokio::time::timeout(WHOIS_TIMEOUT, connect)
        .await
        .map_err(|_| Error::Transport(format!("{host} timed out")))??;
    let payload = format!("{question}\r\n");
    tokio::time::timeout(WHOIS_TIMEOUT, stream.write_all(payload.as_bytes()))
        .await
        .map_err(|_| Error::Transport(format!("{host} timed out")))?
        .map_err(|error| Error::Transport(error.to_string()))?;
    let mut limited = stream.take(MAX_WHOIS_BYTES);
    let mut body = Vec::new();
    tokio::time::timeout(WHOIS_TIMEOUT, limited.read_to_end(&mut body))
        .await
        .map_err(|_| Error::Transport(format!("{host} timed out")))?
        .map_err(|error| Error::Transport(error.to_string()))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Connects to port 43 on `host`, using only its public addresses.
///
/// The registrar server comes from the registry's answer, which the registrar
/// controls, so it must not be able to send this machine to a local service.
async fn connect_public(host: &str) -> Result<TcpStream, Error> {
    let addresses = tokio::net::lookup_host((host, 43))
        .await
        .map_err(|error| Error::Transport(error.to_string()))?;
    let mut last_error = None;
    for address in addresses.filter(|address| Destinations::Public.allows(address.ip())) {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(Error::Transport(last_error.map_or_else(
        || format!("refused WHOIS host {host}: no public address"),
        |error| error.to_string(),
    )))
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && !host.contains(['/', '\\', ':', '@', ' '])
        && host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// `whois:` line from an IANA TLD referral.
pub(crate) fn referred_server(text: &str) -> Option<String> {
    field(text, "whois")
        .into_iter()
        .find_map(|value| host_only(&value))
}

/// `Registrar WHOIS Server` from a registry response.
pub(crate) fn registrar_server(text: &str) -> Option<String> {
    field(text, "registrar whois server")
        .into_iter()
        .find_map(|value| host_only(&value))
}

fn host_only(value: &str) -> Option<String> {
    let host = value
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split(['/', ' '])
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    valid_host(&host).then_some(host)
}

pub(crate) fn parse_whois(text: &str, queried: &str) -> Result<Registration, Error> {
    if not_found(text) {
        return Err(Error::NotFound(queried.to_owned()));
    }
    let domain = published_domain(text).unwrap_or_else(|| queried.to_owned());
    let registrant_name = published(first_field(text, &["registrant name"]));
    let registrant_organization = published(
        first_field(text, &["registrant organization", "registrant org"])
            .or_else(|| first_field(text, &["organisation", "organization"])),
    );
    // Some registrars publish a contact form URL where the email would be.
    let registrant_contact_url = first_field(text, &["registrant email", "registrant contact"])
        .filter(|value| value.to_ascii_lowercase().starts_with("http"))
        .and_then(|url| web_url(&url));
    let dnssec = first_field(text, &["dnssec"]).map(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("signed") && !value.contains("unsigned")
    });
    Ok(Registration {
        domain,
        queried: queried.to_owned(),
        source: Source::Whois,
        registrar: first_field(text, &["registrar"]),
        registrar_id: first_field(text, &["registrar iana id"]),
        statuses: field(text, "domain status")
            .into_iter()
            .filter_map(|status| {
                let code = status.split_whitespace().next()?.to_ascii_lowercase();
                (!code.is_empty()).then_some(code)
            })
            .collect(),
        nameservers: field(text, "name server")
            .into_iter()
            .chain(field(text, "nserver"))
            .filter_map(|server| {
                let host = server
                    .split_whitespace()
                    .next()?
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                (!host.is_empty()).then_some(host)
            })
            .collect(),
        registered_at: first_time(text, &["creation date", "created", "registered"]),
        expires_at: first_time(
            text,
            &[
                "registry expiry date",
                "registrar registration expiration date",
                "expiry date",
                "expiration date",
            ],
        ),
        updated_at: first_time(text, &["updated date", "last updated", "changed"]),
        registrant_name,
        registrant_organization,
        redacted: text_is_redacted(text),
        dnssec,
        ds_records: Vec::new(),
        nameserver_addresses: Vec::new(),
        handle: first_field(text, &["registry domain id"]),
        unicode_name: None,
        registrar_url: first_field(text, &["registrar url"]).and_then(|url| web_url(&url)),
        registrar_country: None,
        whois_server: first_field(text, &["registrar whois server"]),
        abuse_email: published(first_field(text, &["registrar abuse contact email"])),
        abuse_phone: published(first_field(text, &["registrar abuse contact phone"])),
        abuse_url: None,
        registrant_country: published(first_field(text, &["registrant country"])),
        registrant_region: published(first_field(
            text,
            &["registrant state/province", "registrant state"],
        )),
        registrant_contact_url,
        registrar_expires_at: first_time(text, &["registrar registration expiration date"]),
        transferred_at: None,
        database_updated_at: database_updated_at(text),
        registry_source: None,
        registrar_source: None,
    })
}

/// `>>> Last update of whois database: 2026-09-28T21:45:43Z <<<`
fn database_updated_at(text: &str) -> Option<time::OffsetDateTime> {
    text.lines().find_map(|line| {
        let rest = line
            .trim()
            .trim_start_matches('>')
            .trim()
            .strip_prefix("Last update of whois database:")?;
        parse_time(rest.trim().trim_end_matches('<').trim())
    })
}

fn text_is_redacted(text: &str) -> bool {
    [
        "registrant name",
        "registrant organization",
        "organisation",
        "organization",
    ]
    .iter()
    .any(|key| {
        field(text, key)
            .iter()
            .any(|value| is_redacted(Some(value)))
    })
}

fn first_field(text: &str, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| field(text, key).into_iter().next())
}

fn first_time(text: &str, keys: &[&str]) -> Option<time::OffsetDateTime> {
    keys.iter().find_map(|key| {
        field(text, key)
            .into_iter()
            .find_map(|value| parse_time(&value))
    })
}

/// Values for one WHOIS label. Matching ignores case and a trailing colon.
pub(crate) fn field(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let (label, value) = line.split_once(':')?;
            let label = label.trim();
            if !label.eq_ignore_ascii_case(key) {
                return None;
            }
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_owned())
        })
        .collect()
}

fn not_found(text: &str) -> bool {
    if !field(text, "domain name").is_empty() {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    ["no match", "not found", "no data found", "no entries found"]
        .iter()
        .any(|needle| lower.contains(needle))
}

/// The registry record stays authoritative. A registrar referral only adds the
/// registrant fields a thin registry leaves out.
fn merge(registry: Registration, registrar: Registration) -> Registration {
    Registration {
        registrant_name: registrar.registrant_name.or(registry.registrant_name),
        registrant_organization: registrar
            .registrant_organization
            .or(registry.registrant_organization),
        registrant_country: registrar.registrant_country.or(registry.registrant_country),
        registrant_region: registrar.registrant_region.or(registry.registrant_region),
        registrant_contact_url: registrar
            .registrant_contact_url
            .or(registry.registrant_contact_url),
        redacted: registrar.redacted || registry.redacted,
        registrar_url: registry.registrar_url.or(registrar.registrar_url),
        abuse_email: registry.abuse_email.or(registrar.abuse_email),
        abuse_phone: registry.abuse_phone.or(registrar.abuse_phone),
        registrar_expires_at: registrar
            .registrar_expires_at
            .or(registry.registrar_expires_at),
        registrar_source: registrar.registry_source,
        ..registry
    }
}

fn published_domain(text: &str) -> Option<String> {
    field(text, "domain name")
        .into_iter()
        .chain(field(text, "domain"))
        .next()
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const IANA: &str = "\
refer:        whois.verisign-grs.com\n\
whois:        whois.verisign-grs.com\n\
status:       ACTIVE\n";

    const REGISTRY: &str = "\
   Domain Name: EXAMPLE.COM\n\
   Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n\
   Registrar WHOIS Server: whois.iana.org\n\
   Registrar URL: http://res-dom.iana.org\n\
   Registrar Abuse Contact Email: abuse@iana.org\n\
   Registrar Abuse Contact Phone: +1.3108239358\n\
   Updated Date: 2026-08-14T08:01:43Z\n\
   Creation Date: 1995-08-14T04:00:00Z\n\
   Registry Expiry Date: 2027-08-13T04:00:00Z\n\
   Registrar: RESERVED-Internet Assigned Numbers Authority\n\
   Registrar IANA ID: 376\n\
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n\
   Name Server: ELLIOTT.NS.CLOUDFLARE.COM\n\
   DNSSEC: signedDelegation\n\
>>> Last update of whois database: 2026-09-28T21:45:43Z <<<\n";

    #[test]
    fn reads_an_iana_referral_and_a_registry_record() {
        assert_eq!(
            referred_server(IANA).as_deref(),
            Some("whois.verisign-grs.com")
        );
        let record = parse_whois(REGISTRY, "example.com").unwrap();
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.source, Source::Whois);
        assert_eq!(record.registrar_id.as_deref(), Some("376"));
        assert_eq!(record.statuses, ["clientdeleteprohibited"]);
        assert_eq!(record.nameservers, ["elliott.ns.cloudflare.com"]);
        assert_eq!(
            record.registered_at.unwrap().date().to_string(),
            "1995-08-14"
        );
        assert_eq!(record.dnssec, Some(true));
        assert_eq!(
            registrar_server(REGISTRY).as_deref(),
            Some("whois.iana.org")
        );
        assert_eq!(record.handle.as_deref(), Some("2336799_DOMAIN_COM-VRSN"));
        assert_eq!(
            record.registrar_url.as_deref(),
            Some("http://res-dom.iana.org")
        );
        assert_eq!(record.abuse_email.as_deref(), Some("abuse@iana.org"));
        assert_eq!(record.abuse_phone.as_deref(), Some("+1.3108239358"));
        assert_eq!(record.whois_server.as_deref(), Some("whois.iana.org"));
        assert_eq!(
            record.database_updated_at.unwrap().date().to_string(),
            "2026-09-28"
        );
    }

    #[test]
    fn registrant_placeholders_are_not_published_values() {
        let text = "\
Domain Name: EXAMPLE.COM\n\
Registrant Name: REDACTED FOR PRIVACY\n\
Registrant Organization: Example Org LLC\n\
Registrant State/Province: CA\n\
Registrant Country: US\n\
Registrant Email: https://domains.registrar.example/contact/example.com\n";
        let record = parse_whois(text, "example.com").unwrap();
        assert_eq!(record.registrant_name, None);
        assert!(record.redacted);
        assert_eq!(
            record.registrant_organization.as_deref(),
            Some("Example Org LLC")
        );
        assert_eq!(record.registrant_region.as_deref(), Some("CA"));
        assert_eq!(record.registrant_country.as_deref(), Some("US"));
        assert_eq!(
            record.registrant_contact_url.as_deref(),
            Some("https://domains.registrar.example/contact/example.com")
        );
    }

    #[tokio::test]
    #[ignore = "queries whois.iana.org and the .com WHOIS server"]
    async fn example_com_whois_comes_from_the_registry() {
        let record = lookup_whois("example.com").await.unwrap();
        assert_eq!(record.source, Source::Whois);
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.registrar_id.as_deref(), Some("376"));
        assert_eq!(
            record.registered_at.unwrap().date().to_string(),
            "1995-08-14"
        );
    }

    #[test]
    fn a_registrar_referral_does_not_replace_registry_dates() {
        let referral = "\
domain:       EXAMPLE.COM\n\
organisation: Internet Assigned Numbers Authority\n\
created:      1992-01-01\n\
source:       IANA\n";
        let merged = merge(
            parse_whois(REGISTRY, "example.com").unwrap(),
            parse_whois(referral, "example.com").unwrap(),
        );
        assert_eq!(
            merged.registered_at.unwrap().date().to_string(),
            "1995-08-14"
        );
        assert_eq!(merged.registrar_id.as_deref(), Some("376"));
        assert_eq!(
            merged.registrant_organization.as_deref(),
            Some("Internet Assigned Numbers Authority")
        );
    }

    #[test]
    fn a_negative_reply_is_not_a_registration() {
        assert!(matches!(
            parse_whois("No match for MISSING.EXAMPLE.\n", "missing.example"),
            Err(Error::NotFound(_))
        ));
    }

    /// The regression this guards: a registrar referral naming a local host made
    /// the daemon connect to it.
    #[tokio::test]
    async fn local_whois_hosts_are_refused() {
        for host in ["localhost", "127.0.0.1", "10.0.0.1", "169.254.169.254"] {
            let error = connect_public(host).await.expect_err("refused");
            assert!(
                error.to_string().contains("no public address"),
                "{host}: {error}"
            );
        }
    }
}
