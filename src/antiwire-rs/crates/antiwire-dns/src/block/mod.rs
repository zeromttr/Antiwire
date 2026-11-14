//! Policy block responses and block-side-effect plumbing.

mod response;
mod signal;
mod sink;

pub(crate) use response::{build_block_response, BlockResponseMode};
pub(crate) use signal::{BlockSignalLogger, DnsQueryContext};
pub use sink::{DnsBlockSink, DnsHintSink};
