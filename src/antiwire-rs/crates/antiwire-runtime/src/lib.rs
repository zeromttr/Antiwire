//! Process lifecycle for the Antiwire daemon.
//!
//! [`AntiwireRuntime`] starts DNS redirection, firewall rules, flow collection,
//! and background schedulers. Stop cancels everything at once, then reverts
//! host DNS and firewall state (under a hard revert budget) while the workers
//! drain beside it. The runtime is single-use: it cannot be started again
//! after stop or a failed start.

mod context;
mod host_revert;
mod keystore;
mod rule_retarget;
mod runtime;

pub use host_revert::{
    retry_orphaned_host_state, revert_orphaned_host_state, OrphanedPending, OrphanedRevert,
};
pub use runtime::AntiwireRuntime;
