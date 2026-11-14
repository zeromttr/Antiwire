//! Domain inspector results as wire types.

use antiwire_lookup::{CertificateSearchResult, Error as LookupError, Registration};
use antiwire_proto::{
    CertificateHostname, CertificateSearchResponse, DelegationSigner, DnsAnswer, DnsRecordSet,
    DnsRecordsResponse, DomainRegistration, LookupDomainResponse, LookupOutcome, NameserverGlue,
    SeenSubdomain, SeenSubdomainsResponse,
};
use antiwire_services::{CertificateLookup, RegistrationLookup, SeenSubdomains};
use time::OffsetDateTime;

pub(crate) fn registration_lookup_to_proto(
    found: &Result<RegistrationLookup, LookupError>,
) -> LookupDomainResponse {
    match found {
        Ok(found) => LookupDomainResponse {
            outcome: LookupOutcome::Found.into(),
            registration: Some(registration_to_proto(&found.record, found.fetched_at)),
            detail: String::new(),
        },
        Err(error) => LookupDomainResponse {
            outcome: lookup_outcome(error).into(),
            registration: None,
            detail: error.to_string(),
        },
    }
}

pub(crate) fn certificate_lookup_to_proto(lookup: CertificateLookup) -> CertificateSearchResponse {
    match lookup.result {
        Ok(result) => certificates_to_proto(result),
        Err(error) => CertificateSearchResponse {
            outcome: lookup_outcome(&error).into(),
            domain: lookup.domain,
            detail: error.to_string(),
            ..CertificateSearchResponse::default()
        },
    }
}

pub(crate) fn seen_subdomains_to_proto(seen: SeenSubdomains) -> SeenSubdomainsResponse {
    SeenSubdomainsResponse {
        names: seen
            .names
            .into_iter()
            .map(|seen| SeenSubdomain {
                name: seen.name,
                connections: seen.connections,
                blocked: seen.blocked,
                first_seen: unix(seen.first_seen),
                last_seen: unix(seen.last_seen),
            })
            .collect(),
        truncated: seen.truncated,
        domain: seen.domain,
    }
}

pub(crate) fn records_to_proto(lookup: antiwire_dns::RecordLookup) -> DnsRecordsResponse {
    DnsRecordsResponse {
        upstream: lookup.upstream,
        domain: lookup.domain,
        sets: lookup
            .sets
            .into_iter()
            .map(|set| DnsRecordSet {
                purpose: match set.purpose {
                    antiwire_dns::RecordPurpose::Host => "host",
                    antiwire_dns::RecordPurpose::Domain => "domain",
                    antiwire_dns::RecordPurpose::Mail => "mail",
                    antiwire_dns::RecordPurpose::Dkim => "dkim",
                    antiwire_dns::RecordPurpose::Reverse => "reverse",
                }
                .to_owned(),
                name: set.name,
                record_type: set.record_type,
                status: set.status,
                authenticated: set.authenticated,
                answers: set
                    .answers
                    .into_iter()
                    .map(|answer| DnsAnswer {
                        name: answer.name,
                        record_type: answer.record_type,
                        ttl: answer.ttl,
                        data: answer.data,
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn certificates_to_proto(result: CertificateSearchResult) -> CertificateSearchResponse {
    CertificateSearchResponse {
        outcome: LookupOutcome::Found.into(),
        domain: result.domain,
        certificates: result.certificates,
        names: result
            .names
            .into_iter()
            .map(|name| CertificateHostname {
                name: name.name,
                certificates: name.certificates,
                first_issued: unix(name.first_issued),
                latest_expiry: unix(name.latest_expiry),
                issuer: name.issuer.unwrap_or_default(),
            })
            .collect(),
        truncated: result.truncated,
        detail: String::new(),
    }
}

/// Anything that is not a record comes back as an outcome rather than a gRPC
/// error, so the client can explain each one.
fn lookup_outcome(error: &LookupError) -> LookupOutcome {
    match error {
        LookupError::NotFound(_) => LookupOutcome::NotFound,
        LookupError::RateLimited => LookupOutcome::RateLimited,
        LookupError::NoAuthority(_) => LookupOutcome::NoAuthority,
        LookupError::InvalidDomain => LookupOutcome::InvalidDomain,
        _ => LookupOutcome::Unavailable,
    }
}

fn unix(instant: Option<OffsetDateTime>) -> i64 {
    instant.map_or(0, OffsetDateTime::unix_timestamp)
}

fn registration_to_proto(record: &Registration, fetched_at: OffsetDateTime) -> DomainRegistration {
    DomainRegistration {
        domain: record.domain.clone(),
        source: record.source.as_str().to_owned(),
        registrar: text(record.registrar.as_ref()),
        registrar_id: text(record.registrar_id.as_ref()),
        statuses: record.statuses.clone(),
        nameservers: record.nameservers.clone(),
        registered_at: unix(record.registered_at),
        expires_at: unix(record.expires_at),
        updated_at: unix(record.updated_at),
        registrant_name: text(record.registrant_name.as_ref()),
        registrant_organization: text(record.registrant_organization.as_ref()),
        redacted: record.redacted,
        dnssec: match record.dnssec {
            Some(true) => "signed",
            Some(false) => "unsigned",
            None => "",
        }
        .to_owned(),
        fetched_at: fetched_at.unix_timestamp(),
        ds_records: record
            .ds_records
            .iter()
            .map(|ds| DelegationSigner {
                key_tag: ds.key_tag,
                algorithm: u32::from(ds.algorithm),
                digest_type: u32::from(ds.digest_type),
                digest: ds.digest.clone(),
            })
            .collect(),
        nameserver_addresses: record
            .nameserver_addresses
            .iter()
            .map(|glue| NameserverGlue {
                name: glue.name.clone(),
                addresses: glue.addresses.clone(),
            })
            .collect(),
        handle: text(record.handle.as_ref()),
        unicode_name: text(record.unicode_name.as_ref()),
        registrar_url: text(record.registrar_url.as_ref()),
        registrar_country: text(record.registrar_country.as_ref()),
        whois_server: text(record.whois_server.as_ref()),
        abuse_email: text(record.abuse_email.as_ref()),
        abuse_phone: text(record.abuse_phone.as_ref()),
        abuse_url: text(record.abuse_url.as_ref()),
        registrant_country: text(record.registrant_country.as_ref()),
        registrant_region: text(record.registrant_region.as_ref()),
        registrant_contact_url: text(record.registrant_contact_url.as_ref()),
        registrar_expires_at: unix(record.registrar_expires_at),
        transferred_at: unix(record.transferred_at),
        database_updated_at: unix(record.database_updated_at),
        registry_source: text(record.registry_source.as_ref()),
        registrar_source: text(record.registrar_source.as_ref()),
    }
}

fn text(value: Option<&String>) -> String {
    value.cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use antiwire_lookup::Source;
    use time::macros::datetime;

    fn record() -> Registration {
        Registration {
            domain: "example.com".to_owned(),
            queried: "www.example.com".to_owned(),
            source: Source::Rdap,
            registrar: Some("Example Registrar".to_owned()),
            registrar_id: None,
            statuses: vec!["client transfer prohibited".to_owned()],
            nameservers: vec!["a.iana-servers.net".to_owned()],
            registered_at: Some(datetime!(1995-08-14 04:00 UTC)),
            expires_at: None,
            updated_at: None,
            registrant_name: None,
            registrant_organization: None,
            redacted: true,
            dnssec: Some(true),
            ds_records: vec![antiwire_lookup::DsRecord {
                key_tag: 370,
                algorithm: 13,
                digest_type: 2,
                digest: "BE74".to_owned(),
            }],
            nameserver_addresses: Vec::new(),
            handle: Some("2336799_DOMAIN_COM-VRSN".to_owned()),
            unicode_name: None,
            registrar_url: None,
            registrar_country: None,
            whois_server: None,
            abuse_email: Some("abuse@registrar.example".to_owned()),
            abuse_phone: None,
            abuse_url: None,
            registrant_country: Some("US".to_owned()),
            registrant_region: None,
            registrant_contact_url: None,
            registrar_expires_at: None,
            transferred_at: None,
            database_updated_at: None,
            registry_source: Some("https://rdap.example/domain/example.com".to_owned()),
            registrar_source: None,
        }
    }

    #[test]
    fn unpublished_fields_become_empty_and_zero() {
        let fetched = datetime!(2026-09-28 12:00 UTC);
        let proto = registration_to_proto(&record(), fetched);
        assert_eq!(proto.domain, "example.com");
        assert_eq!(proto.source, "rdap");
        assert_eq!(proto.registrar_id, "");
        assert_eq!(proto.registered_at, 808_372_800);
        assert_eq!(proto.expires_at, 0);
        assert_eq!(proto.dnssec, "signed");
        assert!(proto.redacted);
        assert_eq!(proto.fetched_at, fetched.unix_timestamp());
        assert_eq!(proto.handle, "2336799_DOMAIN_COM-VRSN");
        assert_eq!(proto.abuse_email, "abuse@registrar.example");
        assert_eq!(proto.registrant_country, "US");
        assert_eq!(proto.registrar_source, "");
        assert_eq!(proto.transferred_at, 0);
        assert_eq!(proto.ds_records.len(), 1);
        assert_eq!(proto.ds_records[0].algorithm, 13);
    }

    #[test]
    fn registry_failures_map_to_outcomes() {
        let cases = [
            (
                LookupError::NotFound("x.test".to_owned()),
                LookupOutcome::NotFound,
            ),
            (LookupError::RateLimited, LookupOutcome::RateLimited),
            (
                LookupError::NoAuthority("test".to_owned()),
                LookupOutcome::NoAuthority,
            ),
            (
                LookupError::Transport("timeout".to_owned()),
                LookupOutcome::Unavailable,
            ),
            (LookupError::Malformed, LookupOutcome::Unavailable),
            (LookupError::InvalidDomain, LookupOutcome::InvalidDomain),
        ];
        for (error, outcome) in cases {
            let detail = error.to_string();
            let response = registration_lookup_to_proto(&Err(error));
            assert_eq!(response.outcome(), outcome);
            assert!(response.registration.is_none());
            assert_eq!(response.detail, detail);
        }
    }
}
