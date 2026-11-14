//! Cross-cutting platform services: SIEM, retention, queries.

pub mod code_signing;
mod config;
pub mod crash;
#[cfg(windows)]
pub mod process_wait;
mod retention;
mod retention_scheduler;
mod siem;
mod syslog_message;

pub use config::DataPaths;
pub use retention::{purge_connection_logs, RetentionPolicy};
pub use retention_scheduler::RetentionScheduler;
pub use siem::{SiemConfig, SiemExporter, SiemProtocol};
