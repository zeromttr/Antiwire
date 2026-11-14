use thiserror::Error;

#[derive(Debug, Error)]

pub enum StoreError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    #[error("database error: {0}")]
    Database(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("invalid timestamp in database: {0}")]
    InvalidTimestamp(String),

    #[error("firewall rule {0} not found")]
    RuleNotFound(i32),

    #[error("firewall rule {id} cannot be read: {reason}")]
    UnreadableRule { id: i32, reason: String },

    #[error("application {0} not found")]
    ApplicationNotFound(i32),

    #[error("a device watch already covers this address")]
    WatchAlreadyExists,

    #[error("daemon settings row missing")]
    SettingsMissing,

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("keystore error: {0}")]
    KeyStore(#[from] antiwire_secrets::KeyStoreError),
}

pub type Result<T> = std::result::Result<T, StoreError>;
