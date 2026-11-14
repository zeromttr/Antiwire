//! The FLOW listener on Windows architectures without `WinDivert`.
//!
//! The official `WinDivert` 2.2.2 package ships only x86 and x64 drivers, and an ARM64
//! process cannot load the x64 DLL. This build carries no downloader: [`start`] refuses
//! at once with a failure that lasts, so the collector reports the source unavailable a
//! single time and never retries. Flow owners then come from kernel ETW and the socket
//! tables alone.

use std::sync::{Arc, Mutex};

use netmetrics_sys::EventSink;

use crate::divert_error::DivertError;
use crate::flow_owner::FlowOwnerCache;

/// Never constructed: [`start`] always fails on this architecture.
pub(crate) struct FlowListener {
    never: std::convert::Infallible,
}

impl FlowListener {
    pub(crate) fn is_finished(&self) -> bool {
        match self.never {}
    }
}

/// Refuses without touching the network or the disk.
pub(crate) fn start(
    cache: Arc<Mutex<FlowOwnerCache>>,
    sink: EventSink,
) -> Result<FlowListener, DivertError> {
    drop((cache, sink));
    Err(DivertError::lasting(format!(
        "WinDivert is not used on {}: it has no driver for this architecture",
        std::env::consts::ARCH
    )))
}
