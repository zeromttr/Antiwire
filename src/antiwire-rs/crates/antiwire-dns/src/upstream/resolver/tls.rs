//! How the certificate of an encrypted upstream is verified.
//!
//! Every name is resolved over the upstream connection, so verifying that
//! connection's certificate must not need a name resolved. The platform
//! verifier Hickory uses by default does on Windows: it has the OS check the
//! certificate for revocation, and the OS fetches an OCSP response over HTTP
//! from a host it looks up through the system resolver, which is this one. The
//! first handshake after start then waits on a lookup that waits on the
//! handshake, until the OS gives up after ten seconds. Every query in that
//! time runs out its deadline behind the one connection.
//!
//! So the chain is verified here instead, against the OS trust store and with
//! nothing fetched. A certificate authority the user or their organisation
//! installed is still trusted, which a custom upstream may rely on. Revocation
//! is not checked. The platform check did not enforce it either: a response it
//! could not fetch was ignored.

use std::sync::Arc;

use hickory_resolver::TlsConfig;
use rustls::{ClientConfig, RootCertStore};
use tracing::{debug, warn};

use crate::{DnsError, Result};

/// TLS client settings for every encrypted upstream connection.
pub(super) fn upstream_tls_config() -> Result<TlsConfig> {
    let roots = os_trust_store();
    if roots.is_empty() {
        // A resolver that cannot connect is worse than one that verifies the
        // way Hickory does by default.
        warn!("the OS trust store has no usable certificate; verifying dns upstreams with the platform verifier");
        return TlsConfig::new().map_err(|error| tls_error(&error));
    }
    tls_config_trusting(roots)
}

/// The certificate authorities the OS trusts. Read on every call, so one
/// installed while the daemon runs is trusted the next time the upstream
/// pools are built: at the next settings or network change.
fn os_trust_store() -> RootCertStore {
    let loaded = rustls_native_certs::load_native_certs();
    for error in &loaded.errors {
        debug!(%error, "could not read part of the OS trust store");
    }
    let mut roots = RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(loaded.certs);
    debug!(added, ignored, "read the OS trust store for dns upstreams");
    roots
}

/// Settings that verify a server's chain against `roots` alone, offline.
fn tls_config_trusting(roots: RootCertStore) -> Result<TlsConfig> {
    // The provider and protocol versions Hickory builds its own settings with.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| tls_error(&error))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConfig { config })
}

fn tls_error(error: &dyn std::fmt::Display) -> DnsError {
    DnsError::Config(format!(
        "failed to build upstream TLS configuration: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use super::*;

    #[test]
    fn the_settings_build_on_this_host() {
        upstream_tls_config().expect("upstream TLS settings");
    }

    /// The verifier that replaced the platform one must still refuse a
    /// certificate nothing in the trust store vouches for.
    #[test]
    fn a_certificate_no_trusted_authority_issued_is_refused() {
        let roots = os_trust_store();
        if roots.is_empty() {
            // A host with no trust store falls back to Hickory's verifier.
            return;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .expect("verifier");
        // Not a certificate at all, so no chain can be built from it.
        let forged = CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x00]);
        let name = ServerName::try_from("dns.example").expect("name");
        let verdict = verifier.verify_server_cert(&forged, &[], &name, &[], UnixTime::now());
        assert!(verdict.is_err());
    }
}
