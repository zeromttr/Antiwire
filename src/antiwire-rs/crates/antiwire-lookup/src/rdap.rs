//! RDAP domain documents (RFC 9083).

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime};

use crate::error::Error;
use crate::record::{DsRecord, NameserverAddresses, Registration, Source};

/// `{base}/domain/{name}`, with one slash between the base and `domain`.
pub(crate) fn domain_url(base: &str, domain: &str) -> String {
    format!("{}/domain/{domain}", base.trim_end_matches('/'))
}

/// Builds a [`Registration`] from one RDAP domain object read from `url`.
pub(crate) fn parse_rdap(body: &str, queried: &str, url: &str) -> Result<Registration, Error> {
    let value: Value = serde_json::from_str(body).map_err(|_| Error::Malformed)?;
    if error_code(&value) == Some(404) {
        return Err(Error::NotFound(queried.to_owned()));
    }
    if value.get("errorCode").is_some() {
        return Err(Error::Malformed);
    }
    let domain = value
        .get("ldhName")
        .and_then(Value::as_str)
        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .ok_or(Error::Malformed)?;

    let entities = value
        .get("entities")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let registrar = first_role(entities, "registrar");
    let registrant = first_role(entities, "registrant");
    let abuse = registrar
        .and_then(|entity| entity.get("entities")?.as_array())
        .and_then(|nested| nested.iter().find(|entity| has_role(entity, "abuse")))
        .or_else(|| first_role(entities, "abuse"));

    let registrant_name = registrant.and_then(|entity| vcard_text(entity, "fn"));
    let registrant_organization = registrant.and_then(|entity| vcard_text(entity, "org"));
    let registrant_address = registrant.and_then(vcard_address);
    let redacted = value
        .get("redacted")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
        || registrant.is_some_and(entity_has_redactions);

    Ok(Registration {
        domain,
        queried: queried.to_owned(),
        source: Source::Rdap,
        registrar: registrar
            .and_then(|entity| vcard_text(entity, "fn").or_else(|| vcard_text(entity, "org"))),
        registrar_id: registrar.and_then(registrar_id),
        statuses: strings(value.get("status"))
            .into_iter()
            .map(|status| status.to_ascii_lowercase())
            .collect(),
        nameservers: nameservers(&value),
        registered_at: event_time(&value, "registration"),
        expires_at: event_time(&value, "expiration"),
        updated_at: event_time(&value, "last changed"),
        registrant_name: published(registrant_name),
        registrant_organization: published(registrant_organization),
        redacted,
        dnssec: value
            .pointer("/secureDNS/delegationSigned")
            .and_then(Value::as_bool),
        ds_records: ds_records(&value),
        nameserver_addresses: nameserver_addresses(&value),
        handle: text_field(&value, "handle"),
        unicode_name: text_field(&value, "unicodeName")
            .map(|name| name.trim_end_matches('.').to_owned())
            .filter(|name| !name.eq_ignore_ascii_case(value["ldhName"].as_str().unwrap_or(""))),
        registrar_url: registrar.and_then(|entity| {
            link(entity, "about")
                .or_else(|| vcard_text(entity, "url"))
                .and_then(|url| web_url(&url))
        }),
        registrar_country: registrar.and_then(vcard_address).and_then(|a| a.country),
        whois_server: text_field(&value, "port43"),
        abuse_email: published(abuse.and_then(|entity| vcard_text(entity, "email"))),
        abuse_phone: published(abuse.and_then(|entity| vcard_text(entity, "tel")))
            .map(|tel| tel.trim_start_matches("tel:").to_owned()),
        abuse_url: abuse
            .and_then(|entity| vcard_text(entity, "contact-uri"))
            .and_then(|url| web_url(&url)),
        registrant_country: registrant_address.as_ref().and_then(|a| a.country.clone()),
        registrant_region: registrant_address.and_then(|a| a.region),
        registrant_contact_url: registrant
            .and_then(|entity| vcard_text(entity, "contact-uri"))
            .and_then(|url| web_url(&url)),
        registrar_expires_at: event_time(&value, "registrar expiration"),
        transferred_at: event_time(&value, "transfer"),
        database_updated_at: event_time(&value, "last update of RDAP database"),
        registry_source: Some(url.to_owned()),
        registrar_source: None,
    })
}

/// The registrar's own RDAP record for this domain, linked from the registry's.
///
/// Thin registries publish it as a `related` link; only an HTTPS URL for a
/// domain object is followed.
pub(crate) fn registrar_link(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let links = value.get("links")?.as_array()?;
    links.iter().find_map(|item| {
        let rel = item.get("rel")?.as_str()?;
        let href = item.get("href")?.as_str()?.trim();
        let rdap_type = item
            .get("type")
            .and_then(Value::as_str)
            .is_none_or(|kind| kind.contains("rdap") || kind.contains("json"));
        (rel.eq_ignore_ascii_case("related")
            && rdap_type
            && href.starts_with("https://")
            && href.to_ascii_lowercase().contains("/domain/"))
        .then(|| href.to_owned())
    })
}

/// The registry record stays authoritative for dates, statuses and
/// delegation. The registrar's record adds what a thin registry leaves out.
pub(crate) fn merge_registrar(registry: Registration, registrar: Registration) -> Registration {
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
        registrar_country: registrar.registrar_country.or(registry.registrar_country),
        whois_server: registrar.whois_server.or(registry.whois_server),
        abuse_email: registry.abuse_email.or(registrar.abuse_email),
        abuse_phone: registry.abuse_phone.or(registrar.abuse_phone),
        abuse_url: registrar.abuse_url.or(registry.abuse_url),
        registrar_expires_at: registrar
            .registrar_expires_at
            .or(registry.registrar_expires_at),
        transferred_at: registry.transferred_at.or(registrar.transferred_at),
        registrar_source: registrar.registry_source,
        ..registry
    }
}

fn error_code(value: &Value) -> Option<u64> {
    match value.get("errorCode")? {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn text_field(value: &Value, key: &str) -> Option<String> {
    let text = value.get(key)?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn link(entity: &Value, rel: &str) -> Option<String> {
    entity.get("links")?.as_array()?.iter().find_map(|item| {
        let found = item.get("rel")?.as_str()?.eq_ignore_ascii_case(rel);
        found
            .then(|| item.get("href")?.as_str().map(str::to_owned))
            .flatten()
    })
}

/// A web address a person can open; anything but `http`/`https` is dropped.
pub(crate) fn web_url(text: &str) -> Option<String> {
    let text = text.trim();
    let lower = text.to_ascii_lowercase();
    let url = if lower.starts_with("https://") || lower.starts_with("http://") {
        text.to_owned()
    } else if !text.is_empty() && !text.contains([' ', ':', '@']) && text.contains('.') {
        format!("https://{text}")
    } else {
        return None;
    };
    (!url.contains(char::is_whitespace)).then_some(url)
}

fn nameservers(value: &Value) -> Vec<String> {
    value
        .get("nameservers")
        .and_then(Value::as_array)
        .map(|servers| {
            servers
                .iter()
                .filter_map(|server| {
                    server
                        .get("ldhName")
                        .and_then(Value::as_str)
                        .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                })
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn nameserver_addresses(value: &Value) -> Vec<NameserverAddresses> {
    let Some(servers) = value.get("nameservers").and_then(Value::as_array) else {
        return Vec::new();
    };
    servers
        .iter()
        .filter_map(|server| {
            let name = server
                .get("ldhName")?
                .as_str()?
                .trim_end_matches('.')
                .to_ascii_lowercase();
            let ips = server.get("ipAddresses")?;
            let addresses: Vec<String> = strings(ips.get("v4"))
                .into_iter()
                .chain(strings(ips.get("v6")))
                .collect();
            (!name.is_empty() && !addresses.is_empty())
                .then_some(NameserverAddresses { name, addresses })
        })
        .collect()
}

fn ds_records(value: &Value) -> Vec<DsRecord> {
    let Some(items) = value.pointer("/secureDNS/dsData").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let number = |key: &str| item.get(key).and_then(Value::as_u64);
            let digest = item.get("digest")?.as_str()?.trim().to_ascii_uppercase();
            Some(DsRecord {
                key_tag: u32::try_from(number("keyTag")?).ok()?,
                algorithm: u8::try_from(number("algorithm")?).ok()?,
                digest_type: u8::try_from(number("digestType")?).ok()?,
                digest,
            })
        })
        .collect()
}

fn event_time(value: &Value, action: &str) -> Option<OffsetDateTime> {
    let events = value.get("events")?.as_array()?;
    let stamp = events.iter().find_map(|event| {
        let found = event
            .get("eventAction")?
            .as_str()?
            .eq_ignore_ascii_case(action);
        found.then(|| event.get("eventDate")?.as_str()).flatten()
    })?;
    parse_time(stamp)
}

fn first_role<'a>(entities: &'a [Value], role: &str) -> Option<&'a Value> {
    entities
        .iter()
        .find(|entity| has_role(entity, role))
        .or_else(|| {
            entities.iter().find_map(|entity| {
                let nested = entity.get("entities")?.as_array()?;
                nested.iter().find(|entity| has_role(entity, role))
            })
        })
}

fn has_role(entity: &Value, role: &str) -> bool {
    entity
        .get("roles")
        .and_then(Value::as_array)
        .is_some_and(|roles| {
            roles.iter().any(|item| {
                item.as_str()
                    .is_some_and(|text| text.eq_ignore_ascii_case(role))
            })
        })
}

fn registrar_id(entity: &Value) -> Option<String> {
    let ids = entity.get("publicIds")?.as_array()?;
    ids.iter().find_map(|id| {
        let kind = id.get("type")?.as_str()?;
        kind.eq_ignore_ascii_case("IANA Registrar ID")
            .then(|| id.get("identifier")?.as_str().map(str::to_owned))
            .flatten()
    })
}

fn vcard_entries(entity: &Value) -> &[Value] {
    entity
        .get("vcardArray")
        .and_then(|card| card.get(1))
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
}

fn vcard_text(entity: &Value, key: &str) -> Option<String> {
    vcard_entries(entity).iter().find_map(|entry| {
        let fields = entry.as_array()?;
        let name = fields.first()?.as_str()?;
        if !name.eq_ignore_ascii_case(key) {
            return None;
        }
        let text = fields.get(3)?.as_str()?.trim();
        (!text.is_empty()).then(|| text.to_owned())
    })
}

/// The coarse part of a vCard address: country and region. The street,
/// city and postcode are never read.
struct Address {
    country: Option<String>,
    region: Option<String>,
}

fn vcard_address(entity: &Value) -> Option<Address> {
    let fields = vcard_entries(entity).iter().find_map(|entry| {
        let fields = entry.as_array()?;
        fields
            .first()?
            .as_str()?
            .eq_ignore_ascii_case("adr")
            .then_some(fields)
    })?;
    let code = fields
        .get(1)
        .and_then(|params| params.get("cc"))
        .and_then(Value::as_str)
        .map(|code| code.trim().to_ascii_uppercase());
    let parts = fields.get(3).and_then(Value::as_array);
    let part = |index: usize| {
        published(
            parts
                .and_then(|parts| parts.get(index))
                .and_then(Value::as_str)
                .map(|text| text.trim().to_owned())
                .filter(|text| !text.is_empty()),
        )
    };
    let address = Address {
        country: published(code.filter(|code| !code.is_empty())).or_else(|| part(6)),
        region: part(4),
    };
    (address.country.is_some() || address.region.is_some()).then_some(address)
}

/// True when any vCard value on the entity is marked as withheld.
fn entity_has_redactions(entity: &Value) -> bool {
    vcard_entries(entity).iter().any(|entry| {
        entry
            .as_array()
            .and_then(|fields| fields.get(3))
            .is_some_and(|value| match value {
                Value::String(text) => is_redacted(Some(text)),
                Value::Array(parts) => parts.iter().any(|part| is_redacted(part.as_str())),
                _ => false,
            })
    })
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// True for the placeholders registries publish in place of withheld data.
pub(crate) fn is_redacted(value: Option<&str>) -> bool {
    value.is_some_and(|text| {
        let text = text.to_ascii_lowercase();
        [
            "redacted",
            "for privacy",
            "privacy service",
            "not disclosed",
            "withheld",
            "data protected",
            "gdpr masked",
        ]
        .iter()
        .any(|marker| text.contains(marker))
    })
}

/// `None` for a value the source marked as withheld.
pub(crate) fn published(value: Option<String>) -> Option<String> {
    value.filter(|text| !is_redacted(Some(text)))
}

pub(crate) fn parse_time(text: &str) -> Option<OffsetDateTime> {
    let text = text.trim();
    if let Ok(parsed) = OffsetDateTime::parse(text, &Rfc3339) {
        return Some(parsed);
    }
    if let Some((date, time)) = text.split_once(' ') {
        let candidate = if time.ends_with('Z') || time.contains('+') || time.contains('-') {
            format!("{date}T{time}")
        } else {
            format!("{date}T{time}Z")
        };
        if let Ok(parsed) = OffsetDateTime::parse(&candidate, &Rfc3339) {
            return Some(parsed);
        }
    }
    let date_only = text.get(..10)?;
    let mut parts = date_only.split('-');
    let year: i32 = parts.next()?.parse().ok()?;
    let month = Month::try_from(parts.next()?.parse::<u8>().ok()?).ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let date = Date::from_calendar_date(year, month, day).ok()?;
    Some(date.midnight().assume_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "https://rdap.verisign.com/com/v1/domain/example.com";

    const SAMPLE: &str = r#"{
        "ldhName": "EXAMPLE.COM",
        "handle": "2336799_DOMAIN_COM-VRSN",
        "links": [
            {"rel": "self", "href": "https://rdap.verisign.com/com/v1/domain/EXAMPLE.COM"},
            {"rel": "related", "type": "application/rdap+json",
             "href": "https://rdap.registrar.example/rdap/domain/EXAMPLE.COM"}
        ],
        "status": ["client delete prohibited", "client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-08-14T08:01:43Z"},
            {"eventAction": "transfer", "eventDate": "2011-01-05T10:00:00Z"},
            {"eventAction": "last update of RDAP database", "eventDate": "2026-09-23T08:32:35Z"}
        ],
        "entities": [{
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "376"}],
            "links": [{"rel": "about", "href": "http://www.iana.org"}],
            "vcardArray": ["vcard", [
                ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"]
            ]],
            "entities": [{
                "roles": ["abuse"],
                "vcardArray": ["vcard", [
                    ["fn", {}, "text", ""],
                    ["tel", {"type": "voice"}, "uri", "tel:+1.3108239358"],
                    ["email", {}, "text", "abuse@iana.org"]
                ]]
            }]
        }],
        "nameservers": [
            {"ldhName": "ELLIOTT.NS.CLOUDFLARE.COM",
             "ipAddresses": {"v4": ["192.0.2.53"], "v6": ["2001:db8::53"]}},
            {"ldhName": "HERA.NS.CLOUDFLARE.COM"}
        ],
        "secureDNS": {"delegationSigned": true, "dsData": [
            {"keyTag": 370, "algorithm": 13, "digestType": 2,
             "digest": "be74359954660069d5c63d200c39f5603827d7dd02b56f120ee9f3a86764247c"}
        ]},
        "redacted": []
    }"#;

    /// Registrar record, trimmed from a real thick-registrar response.
    const REGISTRAR: &str = r#"{
        "ldhName": "example.com",
        "port43": "whois.registrar.example",
        "events": [
            {"eventAction": "registrar expiration", "eventDate": "2027-08-14T07:00:00.000+00:00"},
            {"eventAction": "registration", "eventDate": "1995-08-14T07:00:00.000+00:00"}
        ],
        "entities": [
            {"roles": ["registrant"], "vcardArray": ["vcard", [
                ["contact-uri", {}, "uri", "https://domains.registrar.example/contact/example.com"],
                ["fn", {}, "text", "REDACTED REGISTRANT"],
                ["org", {"type": "work"}, "text", "Example Org LLC"],
                ["adr", {"cc": "US"}, "text",
                    ["", "", "REDACTED FOR PRIVACY", "REDACTED FOR PRIVACY", "CA", "REDACTED FOR PRIVACY", ""]],
                ["tel", {"type": "voice"}, "text", "REDACTED FOR PRIVACY"],
                ["email", {}, "text", "REDACTED FOR PRIVACY"]
            ]]},
            {"roles": ["registrar"], "vcardArray": ["vcard", [
                ["org", {"type": "work"}, "text", "Registrar Inc."],
                ["adr", {"cc": "us"}, "text", ["", "", "1 Main St", "Town", "ID", "83646", ""]]
            ]], "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [
                ["contact-uri", {"type": "work"}, "uri", "https://registrar.example/abuse-report"]
            ]]}]}
        ]
    }"#;

    #[test]
    fn reads_the_registry_record() {
        let record = parse_rdap(SAMPLE, "www.example.com", URL).unwrap();
        assert_eq!(record.domain, "example.com");
        assert_eq!(record.queried, "www.example.com");
        assert_eq!(record.source, Source::Rdap);
        assert_eq!(
            record.registrar.as_deref(),
            Some("RESERVED-Internet Assigned Numbers Authority")
        );
        assert_eq!(record.registrar_id.as_deref(), Some("376"));
        assert_eq!(
            record.statuses,
            ["client delete prohibited", "client transfer prohibited"]
        );
        assert_eq!(
            record.nameservers,
            ["elliott.ns.cloudflare.com", "hera.ns.cloudflare.com"]
        );
        assert_eq!(
            record.registered_at.unwrap().date().to_string(),
            "1995-08-14"
        );
        assert_eq!(record.expires_at.unwrap().date().to_string(), "2027-08-13");
        assert_eq!(record.dnssec, Some(true));
        assert!(!record.redacted);
    }

    #[test]
    fn reads_the_registry_extras() {
        let record = parse_rdap(SAMPLE, "example.com", URL).unwrap();
        assert_eq!(record.handle.as_deref(), Some("2336799_DOMAIN_COM-VRSN"));
        assert_eq!(record.registrar_url.as_deref(), Some("http://www.iana.org"));
        assert_eq!(record.abuse_email.as_deref(), Some("abuse@iana.org"));
        assert_eq!(record.abuse_phone.as_deref(), Some("+1.3108239358"));
        assert_eq!(
            record.transferred_at.unwrap().date().to_string(),
            "2011-01-05"
        );
        assert_eq!(
            record.database_updated_at.unwrap().date().to_string(),
            "2026-09-23"
        );
        assert_eq!(
            record.ds_records,
            [DsRecord {
                key_tag: 370,
                algorithm: 13,
                digest_type: 2,
                digest: "BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"
                    .to_owned(),
            }]
        );
        assert_eq!(
            record.nameserver_addresses,
            [NameserverAddresses {
                name: "elliott.ns.cloudflare.com".to_owned(),
                addresses: vec!["192.0.2.53".to_owned(), "2001:db8::53".to_owned()],
            }]
        );
        assert_eq!(record.registry_source.as_deref(), Some(URL));
        assert_eq!(
            registrar_link(SAMPLE).as_deref(),
            Some("https://rdap.registrar.example/rdap/domain/EXAMPLE.COM")
        );
    }

    #[test]
    fn the_registrar_record_adds_registrant_details_but_never_personal_contacts() {
        let registry = parse_rdap(SAMPLE, "example.com", URL).unwrap();
        let registrar_url = "https://rdap.registrar.example/rdap/domain/EXAMPLE.COM";
        let registrar = parse_rdap(REGISTRAR, "example.com", registrar_url).unwrap();
        assert_eq!(
            registrar.registrant_name, None,
            "a redacted name is dropped"
        );
        assert!(registrar.redacted);

        let merged = merge_registrar(registry, registrar);
        assert_eq!(
            merged.registrant_organization.as_deref(),
            Some("Example Org LLC")
        );
        assert_eq!(merged.registrant_country.as_deref(), Some("US"));
        assert_eq!(merged.registrant_region.as_deref(), Some("CA"));
        assert_eq!(
            merged.registrant_contact_url.as_deref(),
            Some("https://domains.registrar.example/contact/example.com")
        );
        assert_eq!(merged.registrar_country.as_deref(), Some("US"));
        assert_eq!(
            merged.whois_server.as_deref(),
            Some("whois.registrar.example")
        );
        assert_eq!(
            merged.abuse_url.as_deref(),
            Some("https://registrar.example/abuse-report")
        );
        assert_eq!(
            merged.registrar_expires_at.unwrap().date().to_string(),
            "2027-08-14"
        );
        // Registry facts win.
        assert_eq!(merged.expires_at.unwrap().date().to_string(), "2027-08-13");
        assert_eq!(merged.abuse_email.as_deref(), Some("abuse@iana.org"));
        assert_eq!(merged.handle.as_deref(), Some("2336799_DOMAIN_COM-VRSN"));
        assert_eq!(merged.registry_source.as_deref(), Some(URL));
        assert_eq!(merged.registrar_source.as_deref(), Some(registrar_url));
    }

    #[test]
    fn only_https_domain_links_are_followed() {
        let plain =
            r#"{"links": [{"rel": "related", "href": "http://rdap.example/domain/a.com"}]}"#;
        let other = r#"{"links": [{"rel": "related", "href": "https://rdap.example/entity/1"}]}"#;
        let html = r#"{"links": [{"rel": "related", "type": "text/html",
            "href": "https://rdap.example/domain/a.com"}]}"#;
        assert_eq!(registrar_link(plain), None);
        assert_eq!(registrar_link(other), None);
        assert_eq!(registrar_link(html), None);
    }

    #[test]
    fn only_web_addresses_are_kept_as_links() {
        assert_eq!(
            web_url("www.example.com").as_deref(),
            Some("https://www.example.com")
        );
        assert_eq!(web_url("javascript:alert(1)"), None);
        assert_eq!(web_url("mailto:a@example.com"), None);
    }

    #[test]
    fn an_error_document_is_not_a_registration() {
        let body = r#"{"errorCode": 404, "title": "Not Found"}"#;
        assert!(matches!(
            parse_rdap(body, "missing.example", URL),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn joins_the_domain_path_once() {
        assert_eq!(
            domain_url("https://rdap.verisign.com/com/v1/", "example.com"),
            "https://rdap.verisign.com/com/v1/domain/example.com"
        );
    }
}
