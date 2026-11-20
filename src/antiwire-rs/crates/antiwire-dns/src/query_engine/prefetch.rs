//! Background refresh of cache entries nearing expiry.

use std::sync::Arc;

use antiwire_policy::PolicyEngine;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::DNSClass;
use tracing::warn;

use super::miss::{withheld_answer, Withheld};
use super::QueryEngine;
use crate::provider_block::ProviderFilter;
use crate::rebinding::message_find_rebinding_address;
use crate::response_cache::{
    CacheKey, Fetched, PrefetchReservation, ResponseCache, SharedOutcome, FETCH_GENERATION_ATTEMPTS,
};
use crate::upstream::AdmissionClass;
use crate::{DnsError, Result};

/// EDNS advertised payload size for reconstructed prefetch queries.
const DNS_EDNS_MAX_PAYLOAD: u16 = 1232;

/// What a refresh makes of an answer rebinding protection withholds, or `None`
/// when the answer passes.
///
/// A refresh that sees a private/hint address must not replace the still-fresh
/// public entry with NODATA. It withdraws, so the existing answer stays until
/// it expires, and a query waiting on the refresh resolves the name itself and
/// is answered as the miss path answers it. The configured resolver's own block
/// is the exception: it is what the miss path caches for the name too, so the
/// refresh takes it, and a blocked name is not fetched again in the foreground
/// every time its entry runs out.
fn withheld_refresh(
    request: &Message,
    cache_key: &CacheKey,
    message: &Message,
    provider_filter: ProviderFilter,
) -> Option<Fetched> {
    let ip = message_find_rebinding_address(message)?;
    if provider_filter.is_block(message) {
        let withheld = withheld_answer(request, cache_key.flags.dnssec_ok, Withheld::ProviderBlock);
        return Some(ResponseCache::entry_from_message(&withheld, true).into());
    }
    warn!(%ip, "prefetch discarded rebinding answer; keeping cached entry");
    Some(Fetched::Withdrawn)
}

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    pub(super) fn spawn_prefetch(&self, cache_key: CacheKey, reservation: PrefetchReservation) {
        let cache = Arc::clone(&self.response_cache);
        let upstream_holder = Arc::clone(&self.upstream);
        let rebinding_protection_enabled = self.rebinding_protection_enabled;
        let provider_filter = *self.provider_filter.read();
        let cancellation = self.prefetch_cancel.clone();

        self.prefetch_tasks.spawn(async move {
            let prefetch = async move {
                let Ok(request) = build_query_from_key(&cache_key).map(Arc::new) else {
                    return false;
                };

                // Like the foreground path, every attempt pairs a freshly
                // acquired pool with its generation: a reset between spawn and
                // refresh must not serve the retired network under the new
                // generation. Reads generation before pool for the same
                // reason documented on `current_generation_and_upstream`.
                let mut attempts_remaining = FETCH_GENERATION_ATTEMPTS;
                while attempts_remaining > 0 {
                    attempts_remaining -= 1;
                    let attempt_generation = cache.current_generation();
                    let upstream = Arc::clone(&upstream_holder.read());
                    let outcome = cache
                        .resolve_once(&cache_key, attempt_generation, &|| {
                            let upstream = Arc::clone(&upstream);
                            let request = Arc::clone(&request);
                            let cache = &cache;
                            let cache_key = &cache_key;
                            async move {
                                // A query that misses while this refresh runs
                                // joins it. Failing for want of background
                                // admission, or of a tier slot within a
                                // refresh's short wait, says nothing about the
                                // name, and the query has admission and a wait
                                // of its own: withdraw rather than fail it.
                                let Some(permits) =
                                    upstream.acquire(AdmissionClass::Background, None).await
                                else {
                                    return Fetched::Withdrawn;
                                };
                                let answer = match upstream
                                    .exchange_admitted(request.as_ref(), permits)
                                    .await
                                {
                                    Ok(answer) => answer,
                                    Err(error) if crate::upstream::query_never_sent(&error) => {
                                        return Fetched::Withdrawn;
                                    }
                                    Err(error) => {
                                        cache.record_failure(cache_key, attempt_generation);
                                        return Fetched::Done(Err(DnsError::Upstream(
                                            error.to_string(),
                                        )));
                                    }
                                };
                                let withheld = rebinding_protection_enabled
                                    .then(|| {
                                        withheld_refresh(
                                            request.as_ref(),
                                            cache_key,
                                            &answer.message,
                                            provider_filter,
                                        )
                                    })
                                    .flatten();
                                withheld.unwrap_or_else(|| {
                                    ResponseCache::entry_from_upstream(answer).into()
                                })
                            }
                        })
                        .await;
                    match outcome {
                        SharedOutcome::Ready(result) => return result.is_ok(),
                        // Discarded against a retired generation; retry with a
                        // freshly acquired pair.
                        SharedOutcome::GenerationRetired => {}
                        SharedOutcome::Withdrawn => return false,
                    }
                }
                false
            };

            let succeeded = tokio::select! {
                () = cancellation.cancelled() => false,
                succeeded = prefetch => succeeded,
            };
            reservation.complete(succeeded);
        });
    }
}

pub(super) fn build_query_from_key(key: &CacheKey) -> Result<Message> {
    use hickory_proto::rr::Name;
    let fqdn = Name::from_ascii(format!("{}.", key.domain))
        .map_err(|error| DnsError::InvalidQuery(error.to_string()))?;
    let mut query = Message::new(0, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = key.flags.recursion_desired;
    query.metadata.checking_disabled = key.flags.checking_disabled;
    // Refresh under the same EDNS terms the entry was cached under, so the
    // prefetched answer stays valid for the key it replaces.
    if key.flags.edns {
        let mut edns = Edns::new();
        edns.set_dnssec_ok(key.flags.dnssec_ok);
        edns.set_max_payload(DNS_EDNS_MAX_PAYLOAD);
        query.set_edns(edns);
    }
    let mut rebuilt = Query::query(fqdn, key.qtype);
    rebuilt.set_query_class(DNSClass::from(key.qclass));
    query.add_query(rebuilt);
    Ok(query)
}
