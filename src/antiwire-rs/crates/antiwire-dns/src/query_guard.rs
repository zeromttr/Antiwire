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
use hickory_server::server::Request;
use tracing::error;

static QUERY_PANICS: AtomicU64 = AtomicU64::new(0);

/// Runs one query's handler, returning `None` if it panicked.
///
/// Unwinding runs the same destructors cancelling the query would, and the
/// shared locks on the query path either cannot poison (`parking_lot`) or
/// recover from it, so later queries see the state a cancelled query leaves.
pub(crate) async fn catch_query_panic<F: Future>(request: &Request, query: F) -> Option<F::Output> {
    AssertUnwindSafe(query)
        .catch_unwind()
        .await
        .map_err(|payload| note_panic(request, payload.as_ref()))
        .ok()
}

/// Synchronous [`catch_query_panic`], for the local answer path.
pub(crate) fn catch_sync_query_panic<T>(request: &Request, query: impl FnOnce() -> T) -> Option<T> {
    std::panic::catch_unwind(AssertUnwindSafe(query))
        .map_err(|payload| note_panic(request, payload.as_ref()))
        .ok()
}

fn note_panic(request: &Request, payload: &(dyn Any + Send)) {
    let panics = QUERY_PANICS.fetch_add(1, Ordering::Relaxed) + 1;
    if panics.is_power_of_two() {
        error!(
            panics,
            protocol = %request.protocol(),
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

    fn request() -> Request {
        let mut query = hickory_proto::op::Message::new(
            7,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        query.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("guard.test.").expect("name"),
            hickory_proto::rr::RecordType::A,
        ));
        Request::from_bytes(
            crate::messages::encode_message(&query).expect("encode"),
            "127.0.0.1:53000".parse().expect("address"),
            hickory_server::net::xfer::Protocol::Udp,
        )
        .expect("parse")
    }

    #[tokio::test]
    async fn panics_become_none_on_both_paths() {
        let request = request();
        assert_eq!(catch_sync_query_panic(&request, || 3), Some(3));
        assert_eq!(
            catch_sync_query_panic(&request, || -> u8 { panic!("sync") }),
            None
        );
        assert_eq!(catch_query_panic(&request, async { 4 }).await, Some(4));
        assert_eq!(
            catch_query_panic(&request, async { panic!("async") }).await,
            None::<u8>
        );
    }
}
