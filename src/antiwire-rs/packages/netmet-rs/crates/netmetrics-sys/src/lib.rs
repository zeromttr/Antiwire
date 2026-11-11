//! Internal contract between the public collector and native backends.

mod backend;
/// Shared lifetime and clock adapters for native ownership readers.
#[doc(hidden)]
pub mod endpoint_owner;
#[cfg(unix)]
mod ifindex;
#[cfg(unix)]
mod poll;
mod sink;
mod stop;
mod unavailable;
mod wire;

pub use backend::{Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent};
#[cfg(unix)]
pub use ifindex::interface_index_by_name;
pub use netmetrics_core::{DnsCallerIdentity, DnsCorrelationId, DnsQueryEvent};
#[cfg(unix)]
pub use poll::wait_readable;
pub use sink::{EventGate, EventSink, OrderedIngress, WakeState};
pub use stop::StopFlag;
pub use wire::{
    WIRE_RECORD_LEN, WIRE_RECORD_LEN_V1, WIRE_RECORD_LEN_V2, WIRE_RECORD_LEN_V3, WireFlowKind,
    WireFlowRecord, WireRecordError,
};
