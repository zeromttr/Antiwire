use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeyStoreError {
    #[error("database key must be exactly 32 bytes")]
    InvalidKeyLength,

    #[error("database key file has unsafe permissions")]
    InsecurePermissions,

    #[error("secure random source failed: {0}")]
    Entropy(String),

    #[error("access denied while accessing key at {path}")]
    AccessDenied { path: String },

    #[error("failed to read key from {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to write key to {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to restrict access to {path}: {source}")]
    Acl {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[cfg(windows)]
    #[error("DPAPI operation failed: {0}")]
    Dpapi(String),
}
