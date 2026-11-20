//! In-crate integration tests for the DNS listener, query engine, and policy paths.

pub(crate) mod support;

mod generation_retry;
mod listener_integration;
mod query_engine_integration;
mod rebinding_integration;
