//! Per-query panic isolation for the DNS listeners.
//!
//! Cache hits and policy blocks are answered on the receive task itself, so an
//! unguarded panic in one query ends that socket's listener and every client
//! loses its resolver. Catching it here costs only that query, which the
//! services in [`crate::service`] answer SERVFAIL so the client retries instead
//! of waiting out its timeout.

use std::any::Any;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};

use futures_util::FutureExt;
use tracing::error;

use crate::listener::Transport;

static QUERY_PANICS: AtomicU64 = AtomicU64::new(0);

/// Runs one query's handler, returning `None` if it panicked.
///
/// Unwinding runs the same destructors cancelling the query would, and the
/// shared locks on the query path either cannot poison (`parking_lot`) or
/// recover from it, so later queries see the state a cancelled query leaves.
pub(crate) async fn catch_query_panic<F: Future>(
    transport: Transport,
    query: F,
) -> Option<F::Output> {
    AssertUnwindSafe(query)
        .catch_unwind()
        .await
        .map_err(|payload| note_panic(transport, payload.as_ref()))
        .ok()
}

/// Synchronous [`catch_query_panic`], for the local answer path.
pub(crate) fn catch_sync_query_panic<T>(
    transport: Transport,
    query: impl FnOnce() -> T,
) -> Option<T> {
    std::panic::catch_unwind(AssertUnwindSafe(query))
        .map_err(|payload| note_panic(transport, payload.as_ref()))
        .ok()
}

fn note_panic(transport: Transport, payload: &(dyn Any + Send)) {
    let panics = QUERY_PANICS.fetch_add(1, Ordering::Relaxed) + 1;
    if panics.is_power_of_two() {
        error!(
            panics,
            protocol = transport.as_str(),
            message = panic_message(payload),
            "dns query handler panicked; answered SERVFAIL and kept the listener serving"
        );
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panic_messages_are_extracted_from_str_and_string_payloads() {
        let literal: Box<dyn Any + Send> = Box::new("slice index starts at 1 but ends at 0");
        assert_eq!(
            panic_message(literal.as_ref()),
            "slice index starts at 1 but ends at 0"
        );
        let formatted: Box<dyn Any + Send> = Box::new(format!("index {}", 3));
        assert_eq!(panic_message(formatted.as_ref()), "index 3");
        let other: Box<dyn Any + Send> = Box::new(7_u8);
        assert_eq!(panic_message(other.as_ref()), "non-string panic payload");
    }

    #[tokio::test]
    async fn panics_become_none_on_both_paths() {
        assert_eq!(catch_sync_query_panic(Transport::Udp, || 3), Some(3));
        assert_eq!(
            catch_sync_query_panic(Transport::Udp, || -> u8 { panic!("sync") }),
            None
        );
        assert_eq!(
            catch_query_panic(Transport::Udp, async { 4 }).await,
            Some(4)
        );
        assert_eq!(
            catch_query_panic(Transport::Udp, async { panic!("async") }).await,
            None::<u8>
        );
    }
}
