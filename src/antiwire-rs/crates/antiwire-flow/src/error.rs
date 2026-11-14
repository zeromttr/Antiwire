pub type Result<T> = std::result::Result<T, FlowError>;

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("flow store error: {0}")]
    Store(#[from] antiwire_store::StoreError),
    #[error("netmetrics error: {0}")]
    Metrics(#[from] netmetrics_core::MetricsError),
    #[error("flow collector is already running")]
    AlreadyRunning,
    #[error("invalid flow bridge configuration: {0}")]
    InvalidConfig(String),
    #[error("could not start flow forwarding worker: {0}")]
    WorkerSpawn(#[source] std::io::Error),
}
