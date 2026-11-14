//! Internal contract between the public collector and native backends.

mod backend;
mod background;
mod command;
mod divert_watch;
mod dns_capture;
/// Shared lifetime and clock adapters for native ownership readers.
#[doc(hidden)]
pub mod endpoint_owner;
mod fallback;
#[cfg(unix)]
mod ifindex;
#[cfg(unix)]
mod poll;
mod sink;
mod stop;
mod total;
mod unavailable;
mod wire;

pub use backend::{Backend, BackendConfig, BackendError, BackendErrorKind, BackendEvent};
pub use background::BackgroundRead;
pub use command::{CommandOutput, run_command};
pub use divert_watch::{DIVERT_CHECK_INTERVAL, DivertRules, DivertWatch};
pub use dns_capture::DnsCapture;
pub use fallback::{
    FallbackExit, FlowSources, NATIVE_RETRY_INTERVAL, SnapshotFallback, run_with_fallback,
};
#[cfg(unix)]
pub use ifindex::{InterfaceIndexes, interface_index_by_name};
pub use netmetrics_core::{DnsCallerIdentity, DnsCorrelationId, DnsQueryEvent};
#[cfg(unix)]
pub use poll::wait_readable;
pub use sink::{EventGate, EventSink, OrderedIngress, WakeState};
pub use stop::StopFlag;
pub use total::{RunningTotal, TotalDelta};
pub use wire::{
    WIRE_PROCESS_RECORD_LEN, WIRE_RECORD_LEN, WIRE_RECORD_LEN_V1, WIRE_RECORD_LEN_V2,
    WIRE_RECORD_LEN_V3, WireFlowKind, WireFlowRecord, WireProcessKind, WireProcessRecord,
    WireRecord, WireRecordError,
};
