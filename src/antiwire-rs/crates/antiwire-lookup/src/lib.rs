//! Official domain registration records.
//!
//! Lookups talk only to IANA and to the RDAP or WHOIS server IANA names for
//! that TLD. Registration lookups do not call third-party lookup sites.
//!
//! [`Lookup::lookup`] prefers the registry RDAP record (RFC 9082 / RFC 9083),
//! using the bootstrap file IANA publishes at
//! `https://data.iana.org/rdap/dns.json` (RFC 9224). When that file lists no
//! HTTPS RDAP service, the same fields are read from WHOIS (RFC 3912) on the
//! server `whois.iana.org` refers.
//!
//! [`CertificateSearch`] is the one exception, and is opt-in: it asks crt.sh,
//! a third-party index of Certificate Transparency logs, for the hostnames on
//! a domain's certificates.

mod bootstrap;
mod ct;
mod error;
mod lookup;
mod name;
mod rdap;
mod record;
mod whois;

pub use ct::{CertificateName, CertificateSearch, CertificateSearchResult};
pub use error::Error;
pub use lookup::Lookup;
pub use record::{DsRecord, NameserverAddresses, Registration, Source};
