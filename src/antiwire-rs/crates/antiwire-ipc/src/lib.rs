//! gRPC IPC server, token auth, and streaming RPCs for the Antiwire daemon.

mod atomic_file;
mod auth;
mod endpoint;
mod error;
mod handlers;
#[cfg(any(windows, test))]
mod ipc_tls;
mod proto_bridge;
mod reply;
mod server;
mod service;
mod stream;
#[cfg(any(test, feature = "test-support"))]
mod test_support;

pub use endpoint::{IpcEndpoint, IpcPaths};
pub use error::IpcError;
pub use server::GrpcServer;
pub use service::ServiceParts;
#[cfg(any(test, feature = "test-support"))]
pub use test_support::TestService;
