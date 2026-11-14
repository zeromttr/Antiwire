//! TLS certificate generation and publication for Windows loopback IPC.

use std::fmt;
use std::path::Path;

use rcgen::{generate_simple_self_signed, CertifiedKey};
use zeroize::Zeroizing;

/// A fresh certificate and its private key, for tonic TLS.
pub(crate) struct IpcTlsIdentity {
    pub(crate) cert_pem: String,
    /// Wiped from memory when dropped, and never printed.
    pub(crate) key_pem: Zeroizing<String>,
}

impl fmt::Debug for IpcTlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IpcTlsIdentity")
            .field("cert_pem", &self.cert_pem)
            .field("key_pem", &"[redacted]")
            .finish()
    }
}

/// Generates a fresh localhost self-signed certificate for IPC.
pub(crate) fn generate_server_identity() -> Result<IpcTlsIdentity, rcgen::Error> {
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])?;
    Ok(IpcTlsIdentity {
        cert_pem: cert.pem(),
        key_pem: Zeroizing::new(key_pair.serialize_pem()),
    })
}

/// Writes the public certificate to `path`, where the client pins it.
pub(crate) fn publish_public_cert(path: &Path, cert_pem: &str) -> std::io::Result<()> {
    crate::atomic_file::write_shared_credential(path, cert_pem.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_pem_identity() {
        let identity = generate_server_identity().expect("identity");
        assert!(identity.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(identity.key_pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn the_private_key_is_not_printed() {
        let identity = generate_server_identity().expect("identity");
        let printed = format!("{identity:?}");
        assert!(printed.contains("[redacted]"));
        assert!(!printed.contains("PRIVATE KEY"));
    }

    #[test]
    fn publishes_cert_to_the_given_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("ipc.crt");

        let identity = generate_server_identity().expect("identity");
        publish_public_cert(&cert_path, &identity.cert_pem).expect("publish");

        let contents = std::fs::read_to_string(cert_path).expect("cert file");
        assert!(contents.contains("BEGIN CERTIFICATE"));
    }
}
