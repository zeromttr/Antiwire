use firew_rs::Error as FirewError;

pub type Result<T> = std::result::Result<T, EnforceError>;

#[derive(Debug, thiserror::Error)]
pub enum EnforceError {
    #[error("firewall backend error: {0}")]
    Firewall(#[from] FirewError),
    #[error("invalid enforcement operation: {0}")]
    InvalidOp(String),
    #[error("firewall filter is not started")]
    NotStarted,
    #[error("firewall filter is already started")]
    AlreadyStarted,
    #[error("firewall worker unavailable: {0}")]
    WorkerUnavailable(String),
    /// The worker was closed at shutdown and installs nothing more.
    #[error("firewall enforcement has shut down")]
    Closed,
}
