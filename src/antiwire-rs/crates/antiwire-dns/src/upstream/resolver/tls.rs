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
//! So the chain is verified here instead, with nothing fetched, against the OS
//! trust store and the Mozilla roots compiled into the daemon.
//!
//! The OS store alone is not enough on Windows. It holds only the roots some
//! earlier handshake through the OS needed: Windows downloads each of the
//! others the first time its own chain building meets it, and verifying here
//! never asks it to. A resolver whose chain ends at a root this host has not
//! met yet would be refused, on a fresh install most of all. The compiled-in
//! roots cover the public authorities wherever the daemon runs.
//!
//! The OS store still adds what they lack: a certificate authority the user or
//! their organisation installed, which a custom upstream may rely on. A public
//! root removed from the OS store stays trusted here. Revocation is not
//! checked. The platform check did not enforce it either: a response it could
//! not fetch was ignored.

use std::sync::Arc;

use hickory_resolver::TlsConfig;
use rustls::{ClientConfig, RootCertStore};
use tracing::debug;

use crate::{DnsError, Result};

/// TLS client settings for every encrypted upstream connection.
pub(super) fn upstream_tls_config() -> Result<TlsConfig> {
    tls_config_trusting(with_compiled_in_roots(os_trust_store()))
}

/// `roots`, plus every Mozilla root compiled into the daemon.
fn with_compiled_in_roots(mut roots: RootCertStore) -> RootCertStore {
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
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

    /// A host whose OS store holds no usable root still verifies against the
    /// compiled-in ones.
    #[test]
    fn the_compiled_in_roots_are_trusted_without_an_os_store() {
        let roots = with_compiled_in_roots(RootCertStore::empty());
        assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len());
        assert!(!roots.is_empty());
    }

    /// The verifier that replaced the platform one must still refuse a
    /// certificate nothing in the trust store vouches for.
    #[test]
    fn a_certificate_no_trusted_authority_issued_is_refused() {
        let roots = with_compiled_in_roots(os_trust_store());
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
