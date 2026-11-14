use time::OffsetDateTime;

/// Where a [`Registration`] was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Registry RDAP server named by the IANA bootstrap.
    Rdap,
    /// WHOIS server named by IANA, or the registrar server that response refers to.
    Whois,
}

impl Source {
    /// The protocol's lowercase name, as saved and shown: `rdap` or `whois`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rdap => "rdap",
            Self::Whois => "whois",
        }
    }
}

/// One DNSSEC delegation signer record (RFC 4034) published by the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    pub key_tag: u32,
    /// DNSSEC algorithm number, e.g. 13 for ECDSA P-256 with SHA-256.
    pub algorithm: u8,
    /// Digest algorithm number, e.g. 2 for SHA-256.
    pub digest_type: u8,
    /// Hex digest, uppercase.
    pub digest: String,
}

/// Glue addresses the registry publishes for one name server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameserverAddresses {
    pub name: String,
    pub addresses: Vec<String>,
}

/// Registration facts published by the registry or its registrar.
///
/// A registrant's email, telephone and street address are never copied out
/// of the record, and values the source marks as redacted are left out. The
/// registrar's abuse contact is the registrar's published business contact,
/// not a person's, and is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// Registered name the record describes.
    pub domain: String,
    /// Hostname that was asked for, after normalization.
    pub queried: String,
    /// Protocol that produced this record.
    pub source: Source,
    /// Registrar name, when the registry publishes one.
    pub registrar: Option<String>,
    /// IANA registrar id, when the registry publishes one.
    pub registrar_id: Option<String>,
    /// EPP-style status codes, lowercase.
    pub statuses: Vec<String>,
    /// Delegated name servers, lowercase.
    pub nameservers: Vec<String>,
    /// Registration instant.
    pub registered_at: Option<OffsetDateTime>,
    /// Expiration instant.
    pub expires_at: Option<OffsetDateTime>,
    /// Last change instant published by the registry.
    pub updated_at: Option<OffsetDateTime>,
    /// Registrant name, when the registry publishes one.
    pub registrant_name: Option<String>,
    /// Registrant organization, when the registry publishes one.
    pub registrant_organization: Option<String>,
    /// The registry marked registrant data as redacted.
    pub redacted: bool,
    /// `Some(true)` when the delegation is signed.
    pub dnssec: Option<bool>,
    /// Delegation signer records, when the delegation is signed.
    pub ds_records: Vec<DsRecord>,
    /// Name servers the registry publishes addresses for.
    pub nameserver_addresses: Vec<NameserverAddresses>,
    /// Registry object id, e.g. `2138514_DOMAIN_COM-VRSN`.
    pub handle: Option<String>,
    /// Unicode form of an internationalized name.
    pub unicode_name: Option<String>,
    /// Registrar's website.
    pub registrar_url: Option<String>,
    /// Registrar's country, ISO 3166-1 alpha-2 when the source gives a code.
    pub registrar_country: Option<String>,
    /// Registrar's WHOIS server.
    pub whois_server: Option<String>,
    /// Registrar's published abuse mailbox.
    pub abuse_email: Option<String>,
    /// Registrar's published abuse telephone line.
    pub abuse_phone: Option<String>,
    /// Registrar's abuse report page.
    pub abuse_url: Option<String>,
    /// Registrant country, ISO 3166-1 alpha-2 when the source gives a code.
    pub registrant_country: Option<String>,
    /// Registrant state or province.
    pub registrant_region: Option<String>,
    /// Registrar-hosted form for contacting the registrant.
    pub registrant_contact_url: Option<String>,
    /// Expiration in the registrar's own record, which can differ from the registry's.
    pub registrar_expires_at: Option<OffsetDateTime>,
    /// Last transfer between registrars.
    pub transferred_at: Option<OffsetDateTime>,
    /// When the source last refreshed the record it served.
    pub database_updated_at: Option<OffsetDateTime>,
    /// Registry record that was read: its RDAP URL, or its WHOIS server.
    pub registry_source: Option<String>,
    /// Registrar record merged in: its RDAP URL, or its WHOIS server.
    pub registrar_source: Option<String>,
}
