//! Native FFI wrappers. All `unsafe` for Windows firewall APIs lives here.

#![allow(unsafe_code)]

mod com;
mod wfp;

pub(crate) use com::{needs_set_mode, ComInetFwSession, InetFwNativeRow};
pub(crate) use wfp::{layers_for_empty_remote, WfpEngine};
