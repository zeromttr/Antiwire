//! Errors produced while preparing or serving the local IPC endpoint.

/// IPC initialization and serving failure.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("IPC file operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("OS random source failed: {0}")]
    Random(String),
    /// The listen address is not one this platform serves.
    #[error("invalid IPC endpoint {0}")]
    Endpoint(String),
    #[error("IPC certificate generation failed: {0}")]
    Certificate(#[source] Box<rcgen::Error>),
    #[error("IPC transport failed: {0}")]
    Transport(#[source] Box<tonic::transport::Error>),
    #[error("IPC service initialization failed: {context}")]
    Initialization {
        /// What was being initialized when the failure happened.
        context: &'static str,
        /// The underlying store or enforcement failure.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl From<tonic::transport::Error> for IpcError {
    fn from(error: tonic::transport::Error) -> Self {
        Self::Transport(Box::new(error))
    }
}

impl From<rcgen::Error> for IpcError {
    fn from(error: rcgen::Error) -> Self {
        Self::Certificate(Box::new(error))
    }
}
