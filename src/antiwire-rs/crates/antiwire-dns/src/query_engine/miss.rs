//! The asynchronous miss path: stale serving while the upstream is down, and
//! the generation-aware upstream fetch.

use std::time::{Duration, Instant};

use antiwire_policy::PolicyEngine;
use antiwire_tuning::{
    DNS_QUERY_DEADLINE, DNS_STALE_ANSWER_TIMER, DNS_STALE_ANSWER_TIMER_WHILE_FAILING,
};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use tracing::{debug, info, warn};

use super::ai::answer_is_ai_eligible;
use super::request::PreparedQuery;
use super::response::{prepare_cached_message, prepare_uncached_message, PreparedResponse};
use super::QueryEngine;
use crate::block::DnsQueryContext;
use crate::messages::{build_nodata_response, build_servfail_response};
use crate::port_mapper::QueryClient;
use crate::rebinding::message_find_rebinding_address;
use crate::response_cache::{
    CacheKey, CacheProbe, CachedAnswer, ResponseCache, SharedOutcome, FETCH_GENERATION_ATTEMPTS,
};
use crate::upstream::{AdmissionClass, SharedUpstreamAdmission};
use crate::{DnsError, Result};

/// One miss's upstream work, borrowed by every attempt of its
/// generation-retry loop.
struct MissFetch<'a> {
    request: &'a Message,
    cache_key: &'a CacheKey,
    qtype: RecordType,
    context: Option<DnsQueryContext>,
    cache_eligible: bool,
}

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// Completes a miss returned by [`Self::try_handle_parsed_sync`].
    pub(crate) async fn handle_parsed_miss(
        &self,
        request: &Message,
        context: Option<DnsQueryContext>,
        prepared: PreparedQuery,
        enqueued_at: Instant,
    ) -> PreparedResponse {
        // The gates precede cache/prefetch/upstream: a block prevents any
        // upstream request, and a pass continues normal resolution.
        if let Some((block, post_ai)) = self
            .gates_block(request, &prepared, context, enqueued_at)
            .await
        {
            return prepare_uncached_message(block, post_ai);
        }
        let post_ai = self.post_work_for_domain_key(&prepared.cache_key.domain, false);
        let domain = prepared.cache_key.domain.clone();
        match self
            .resolve_miss_entry(request, context, prepared, enqueued_at)
            .await
        {
            Some(entry) => {
                self.note_client_hint(context.map(QueryClient::scanned_here), &domain, &entry);
                let post_ai = post_ai.filter(|_| answer_is_ai_eligible(&entry));
                prepare_cached_message(entry, request, post_ai)
            }
            // Locally generated SERVFAIL is excluded from AI learning.
            None => prepare_uncached_message(build_servfail_response(request), None),
        }
    }

    async fn resolve_miss_entry(
        &self,
        request: &Message,
        context: Option<DnsQueryContext>,
        prepared: PreparedQuery,
        enqueued_at: Instant,
    ) -> Option<CachedAnswer> {
        let remaining = remaining_deadline(enqueued_at);
        let cache_key = prepared.cache_key.clone();
        let cache_eligible = prepared.cache_eligible;
        let qtype = prepared.qtype;
        if remaining.is_zero() {
            note_query_timeout(&cache_key.domain, qtype, enqueued_at);
            return self.stale_fallback(&cache_key, cache_eligible);
        }
        // RFC 8767 §5: with a stale answer to fall back on, the client waits
        // no longer than the client response timer, and the refresh goes on
        // in the background.
        let stale_timer = self
            .stale_fallback(&cache_key, cache_eligible)
            .is_some()
            .then(|| {
                self.stale_answer_timer()
                    .saturating_sub(enqueued_at.elapsed())
            })
            .filter(|timer| *timer < remaining);
        tokio::select! {
            biased;
            result = self.handle_miss(request, context, prepared, enqueued_at) => result,
            () = sleep_or_pending(stale_timer) => {
                note_query_timeout(&cache_key.domain, qtype, enqueued_at);
                let stale = self.stale_fallback(&cache_key, cache_eligible);
                if let Some(reservation) = stale
                    .as_ref()
                    .and_then(|_| self.response_cache.try_reserve_prefetch(&cache_key))
                {
                    self.spawn_prefetch(cache_key.clone(), reservation);
                }
                stale
            }
            () = tokio::time::sleep(remaining) => {
                // Inner exchange uses the leftover budget so its timeout
                // usually completes first and already recorded. Prefer that
                // when both fire in the same tick; this branch is the safety
                // net for admission waits and coalesced in-flight joins.
                note_query_timeout(&cache_key.domain, qtype, enqueued_at);
                self.stale_fallback(&cache_key, cache_eligible)
            }
        }
    }

    /// The RFC 8767 §5 client response timer for a query starting now: the
    /// RFC's, or a shorter one while the upstream is failing (see
    /// [`DNS_STALE_ANSWER_TIMER_WHILE_FAILING`]).
    fn stale_answer_timer(&self) -> Duration {
        if self.upstream().failing() {
            DNS_STALE_ANSWER_TIMER_WHILE_FAILING
        } else {
            DNS_STALE_ANSWER_TIMER
        }
    }

    /// Completes a cache miss: probes again, admits the miss rate, then runs
    /// the generation-aware fetch loop.
    async fn handle_miss(
        &self,
        request: &Message,
        context: Option<DnsQueryContext>,
        prepared: PreparedQuery,
        enqueued_at: Instant,
    ) -> Option<CachedAnswer> {
        let PreparedQuery {
            qtype,
            cache_key,
            cache_eligible,
            explicit_allow: _,
        } = prepared;

        // The miss may run detached after queueing; a concurrent query can have
        // filled the cache since the sync probe, and resolve_or_fetch only
        // coalesces in-flight fetches.
        if cache_eligible {
            if let CacheProbe::Fresh(entry) = self.probe_cache(&cache_key) {
                return Some(entry);
            }
            // The name failed while this query was queued; see `process_core`.
            if self.response_cache.failure_held(&cache_key) {
                return self.stale_fallback(&cache_key, cache_eligible);
            }
        }

        // Pool for the degraded-mode fast path below; the fetch loop
        // re-acquires the pool together with its generation on every attempt.
        let upstream = self.upstream();

        // RFC 8767 §5.3-style degraded mode. When every upstream tier is down,
        // serve a stale answer immediately. A cold miss may own a tier's one
        // recovery attempt and spend only the leftover deadline; other
        // requests fail fast inside `exchange` while that attempt runs.
        if let Some(stale) =
            self.serve_stale_while_degraded(&upstream, &cache_key, qtype, cache_eligible)
        {
            return Some(stale);
        }

        let miss = MissFetch {
            request,
            cache_key: &cache_key,
            qtype,
            context,
            cache_eligible,
        };
        self.fetch_with_generation_retries(&miss, enqueued_at).await
    }

    /// Serves a stale answer instead of a real miss when all upstreams are down.
    fn serve_stale_while_degraded(
        &self,
        upstream: &SharedUpstreamAdmission,
        cache_key: &CacheKey,
        qtype: RecordType,
        cache_eligible: bool,
    ) -> Option<CachedAnswer> {
        if !(upstream.degraded() && cache_eligible) {
            return None;
        }
        let stale = self.response_cache.stale_after_failure(cache_key)?;
        info!(
            domain = %cache_key.domain,
            qtype = ?qtype,
            "serving stale answer while every dns upstream tier is down"
        );
        if let Some(reservation) = self.response_cache.try_reserve_prefetch(cache_key) {
            self.spawn_prefetch(cache_key.clone(), reservation);
        }
        Some(stale)
    }

    /// Runs the fetch loop, re-acquiring the upstream pool together with the
    /// generation it is valid for on every attempt.
    ///
    /// A network reset between attempts must not route the retry through the
    /// retired pool: its answer would be resolved over the old network yet
    /// admitted under the new generation. Genuine upstream errors are never
    /// retried; the budget bounds only generation retirements.
    async fn fetch_with_generation_retries(
        &self,
        miss: &MissFetch<'_>,
        enqueued_at: Instant,
    ) -> Option<CachedAnswer> {
        let cache_key = miss.cache_key;
        let mut attempts_remaining = FETCH_GENERATION_ATTEMPTS;
        let mut fetched_for_itself = false;
        while attempts_remaining > 0 {
            attempts_remaining -= 1;
            let (attempt_generation, attempt_upstream) = self.current_generation_and_upstream();
            if !miss.cache_eligible {
                return self
                    .fetch_upstream(miss, &attempt_upstream, attempt_generation, enqueued_at)
                    .await
                    .ok();
            }
            match self
                .response_cache
                .resolve_once(cache_key, attempt_generation, &|| {
                    self.fetch_upstream(miss, &attempt_upstream, attempt_generation, enqueued_at)
                })
                .await
            {
                SharedOutcome::Ready(Ok(entry)) => return Some(entry),
                // The answer was resolved over a retired network and discarded;
                // loop around and retry with a freshly acquired pair.
                SharedOutcome::GenerationRetired => {}
                // A background refresh this miss joined gave up for reasons of
                // its own. Fetch under the miss's own admission and deadline,
                // once, without spending a generation attempt on it.
                SharedOutcome::Withdrawn if !fetched_for_itself => {
                    fetched_for_itself = true;
                    attempts_remaining += 1;
                }
                // Genuine upstream errors are never retried; like any other
                // failure they fall back to a stale answer when one exists.
                SharedOutcome::Ready(Err(_)) | SharedOutcome::Withdrawn => {
                    return self.stale_fallback(cache_key, miss.cache_eligible);
                }
            }
        }

        self.stale_fallback(cache_key, miss.cache_eligible)
    }

    /// One upstream attempt for a miss, including rebinding filtering and
    /// resolution recording.
    async fn fetch_upstream(
        &self,
        miss: &MissFetch<'_>,
        upstream: &SharedUpstreamAdmission,
        generation: u64,
        enqueued_at: Instant,
    ) -> Result<CachedAnswer> {
        let domain = &miss.cache_key.domain;
        let answer = upstream
            .exchange(
                miss.request,
                AdmissionClass::Foreground,
                Some(remaining_deadline(enqueued_at)),
            )
            .await
            .map_err(|error| {
                // NXDOMAIN and NODATA never arrive here as errors: the
                // upstream layer rebuilds them into `Ok` responses that keep
                // the authority SOA, so they get an RFC 2308 negative TTL.
                // Handling them again here would only discard that SOA.
                debug!(
                    domain = %domain,
                    error = %error,
                    "dns upstream lookup failed"
                );
                // Recorded here, once per fetch, rather than by every waiter
                // coalesced onto it.
                if miss.cache_eligible && !crate::upstream::query_never_sent(&error) {
                    self.response_cache
                        .record_failure(miss.cache_key, generation);
                }
                DnsError::Upstream(error.to_string())
            })?;
        let message = &answer.message;
        // Decided before rebinding protection looks at the answer: a filtering
        // resolver's `0.0.0.0` is also an address that protection withholds,
        // and it must be reported as the provider's block, not as an attack.
        let provider_block = self.provider_filter.read().is_block(message);
        if let Some(withheld) = self.withhold_rebinding(miss, message, provider_block) {
            return ResponseCache::entry_from_message(&withheld, true);
        }
        if provider_block {
            self.record_block_resolution(domain, message);
            self.signal_provider_block(miss);
        }
        ResponseCache::entry_from_upstream(answer)
    }

    fn signal_provider_block(&self, miss: &MissFetch<'_>) {
        self.block_signals.signal_block(
            &miss.cache_key.domain,
            miss.qtype,
            Some("dns_provider"),
            self.block_mode,
            miss.context.map(QueryClient::scanned_here),
            || vec![crate::provider_block::DNS_PROVIDER_BLOCK_LABEL.to_owned()],
        );
    }

    /// Replaces an answer that rebinding protection withholds with NODATA.
    ///
    /// A provider block is withheld like any other answer naming such an
    /// address: an attacker's `0.0.0.0` looks the same as a provider's, so
    /// passing it on would open the hole the protection closes. Only what is
    /// reported differs.
    fn withhold_rebinding(
        &self,
        miss: &MissFetch<'_>,
        message: &Message,
        provider_block: bool,
    ) -> Option<Message> {
        if !self.rebinding_protection_enabled {
            return None;
        }
        let domain = &miss.cache_key.domain;
        let ip = message_find_rebinding_address(message)?;
        let reason = if provider_block {
            self.signal_provider_block(miss);
            Withheld::ProviderBlock
        } else {
            warn!(
                domain = %domain,
                %ip,
                "dns rebinding protection blocked upstream answer"
            );
            self.block_signals.signal_block(
                domain,
                miss.qtype,
                Some("dns_rebinding"),
                self.block_mode,
                miss.context.map(QueryClient::scanned_here),
                Vec::new,
            );
            Withheld::Rebinding
        };
        Some(withheld_answer(
            miss.request,
            miss.cache_key.flags.dnssec_ok,
            reason,
        ))
    }

    /// Falls back to a stale answer within its grace window, when eligible.
    fn stale_fallback(&self, cache_key: &CacheKey, cache_eligible: bool) -> Option<CachedAnswer> {
        cache_eligible
            .then(|| self.response_cache.stale_after_failure(cache_key))
            .flatten()
    }
}

/// Why rebinding protection withheld an upstream answer.
#[derive(Clone, Copy)]
pub(super) enum Withheld {
    /// It resolves a public name into the local network.
    Rebinding,
    /// It is the configured resolver's own block, answered with an address
    /// the protection withholds.
    ProviderBlock,
}

/// NODATA in place of an upstream answer that rebinding protection withholds,
/// with an RFC 8914 error that says why.
pub(super) fn withheld_answer(request: &Message, dnssec_ok: bool, reason: Withheld) -> Message {
    let mut nodata = build_nodata_response(request);
    // This answer is cached and replayed to every client sharing the key, so
    // none of this client's options (its ECS subnet, padding, keepalive) may
    // ride along. `response_edns` sets the payload size per client on the way
    // out.
    let mut edns = hickory_proto::op::Edns::new();
    edns.set_dnssec_ok(dnssec_ok);
    let (code, text) = match reason {
        Withheld::Rebinding => (crate::ede::EDE_FILTERED, "Antiwire: DNS Rebinding Filtered"),
        Withheld::ProviderBlock => (crate::ede::EDE_BLOCKED, "Antiwire: Blocked by DNS Provider"),
    };
    edns.options_mut()
        .insert(crate::ede::build_ede_option(code, Some(text)));
    nodata.set_edns(edns);
    nodata
}

fn note_query_timeout(domain: &str, qtype: RecordType, enqueued_at: Instant) {
    debug!(
        domain = %domain,
        qtype = ?qtype,
        elapsed_ms = u64::try_from(enqueued_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        deadline_ms = u64::try_from(DNS_QUERY_DEADLINE.as_millis()).unwrap_or(u64::MAX),
        "dns query deadline expired before upstream answered"
    );
}

async fn sleep_or_pending(timer: Option<Duration>) {
    match timer {
        Some(timer) => tokio::time::sleep(timer).await,
        None => std::future::pending().await,
    }
}

pub(super) fn remaining_deadline(enqueued_at: Instant) -> Duration {
    DNS_QUERY_DEADLINE
        .checked_sub(enqueued_at.elapsed())
        .unwrap_or(Duration::ZERO)
}
