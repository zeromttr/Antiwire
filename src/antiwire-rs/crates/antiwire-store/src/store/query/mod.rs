//! Query methods on [`Store`](super::Store), grouped by domain.
//!
//! Each file holds one or more inherent `impl Store` blocks; the split is
//! purely organizational. Every module here is a child of `store`, so they
//! all share its private database handle without any visibility changes.

mod activity;
mod alerts;
mod applications;
mod connection_logs;
mod country_statistics;
mod dns;
mod dns_redirect;
pub(crate) mod domain_decisions;
mod firewall;
mod history;
mod network;
mod retention;
mod settings;
mod subdomains;

pub use domain_decisions::{DeletionFence, OutcomeRevision, Resident, ResidentDecision};
pub use subdomains::SeenSubdomain;
