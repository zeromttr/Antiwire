//! Policy block responses and block-side-effect plumbing.

mod response;
mod signal;
mod sink;

pub(crate) use response::{build_block_response, BlockResponseMode};
pub(crate) use signal::{BlockSignalLogger, DnsQueryContext};
pub use sink::{DnsBlockSink, DnsHintSink};

/// Drops the answers the operating system's resolver has cached, after a change to which
/// names are blocked.
///
/// A block answer and the answer it replaces are both cacheable, so without this the old
/// outcome stands in the system's cache until its TTL runs out: a name stays unreachable
/// after it is unblocked, or reachable after it is blocked. A program's own cache, such as
/// a browser's, is out of reach and ends with the TTL. Runs the system's flush, which
/// starts a process on Linux and macOS, so call it off the async runtime.
pub fn forget_cached_answers() {
    antiwire_dns_redirect::flush_cache();
}
