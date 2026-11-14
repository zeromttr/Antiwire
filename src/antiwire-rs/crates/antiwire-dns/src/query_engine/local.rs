//! The synchronous path: everything answered without upstream I/O — request
//! validation, policy blocks, special-use names, cache hits, and fail-fast
//! SERVFAILs while every upstream is down.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use antiwire_policy::{DomainBlockSource, PolicyEngine, Verdict};
use antiwire_tuning::{DNS_FAIL_FAST_REPLY_BUDGET, DNS_FAIL_FAST_REPLY_WINDOW};
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_server::net::xfer::Protocol;
use hickory_server::zone_handler::MessageRequest;
use tracing::warn;

use super::ai::AiLocal;
use super::request::{parse_query, validate_request, PreparedQuery, RequestView};
use super::response::{prepare_cached_message, prepare_uncached_message, PreparedResponse};
use super::QueryEngine;
use crate::ai::PostResponseWork;
use crate::block::{build_block_response, BlockResponseMode, DnsQueryContext};
use crate::messages::{
    build_any_response, build_cached_failure_response, build_error_response,
    build_servfail_response,
};
use crate::new_domain::NewDomainVerdict;
use crate::response_cache::{CacheKey, CacheProbe, CachedAnswer};

pub(super) enum CoreSyncOutcome {
    Response(Message, Option<PostResponseWork>),
    /// A cache hit carries only optional background work. With AI disabled,
    /// this stays a compact `None` and does not copy the inline domain key.
    Cached(CachedAnswer, Option<PostResponseWork>),
    Miss(PreparedQuery),
    /// Owed no reply: a UDP miss past the fail-fast reply budget.
    Dropped,
}

/// Caps the SERVFAILs answered for UDP misses while every upstream is down.
///
/// Each reply costs a send on the listener's receive loop. Under a flood of
/// uncached names, answering every one slows the loop until the socket
/// overflows and cached answers are dropped with the flood; dropping the
/// excess keeps the loop draining, as a full worker pool does when the
/// upstream is merely slow. Ordinary traffic stays far below the cap and still
/// fails fast.
pub(super) struct FailFastBudget {
    epoch: Instant,
    window: AtomicU64,
    used: AtomicU32,
    /// Queries dropped past the cap over the engine's lifetime.
    dropped: AtomicU64,
}

impl FailFastBudget {
    pub(super) fn new() -> Self {
        Self {
            epoch: Instant::now(),
            window: AtomicU64::new(0),
            used: AtomicU32::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    /// Counts a query dropped past the cap and returns the running total.
    ///
    /// Logged at the first drop and then at every power of two, like the
    /// listener's other drop paths, so a sustained flood stays visible without
    /// a line per query.
    pub(super) fn note_drop(&self) -> u64 {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped.is_power_of_two() {
            warn!(
                dropped,
                budget = DNS_FAIL_FAST_REPLY_BUDGET,
                window_ms =
                    u64::try_from(DNS_FAIL_FAST_REPLY_WINDOW.as_millis()).unwrap_or(u64::MAX),
                "every dns upstream is down; dropping udp queries past the servfail budget"
            );
        }
        dropped
    }

    fn try_take(&self) -> bool {
        self.try_take_at(self.epoch.elapsed())
    }

    /// Fixed windows: a reset racing another taker can admit a few extra
    /// replies at a boundary, which is harmless for a flood guard.
    pub(super) fn try_take_at(&self, elapsed: Duration) -> bool {
        let window =
            u64::try_from(elapsed.as_millis() / DNS_FAIL_FAST_REPLY_WINDOW.as_millis().max(1))
                .unwrap_or(u64::MAX);
        let current = self.window.load(Ordering::Acquire);
        if current != window
            && self
                .window
                .compare_exchange(current, window, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            self.used.store(0, Ordering::Release);
        }
        self.used.fetch_add(1, Ordering::AcqRel) < DNS_FAIL_FAST_REPLY_BUDGET
    }
}

/// A block answered by an asynchronous gate on the miss path, with the
/// post-response work it carries.
pub(super) type GateBlock = (Message, Option<PostResponseWork>);

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    pub(super) fn process_core<R>(
        &self,
        request: &R,
        context: Option<DnsQueryContext>,
    ) -> CoreSyncOutcome
    where
        R: RequestView,
    {
        if let Some(rcode) = validate_request(request) {
            return CoreSyncOutcome::Response(
                build_error_response(&request.to_message(), rcode),
                None,
            );
        }

        let Ok(mut prepared) = parse_query(request) else {
            return CoreSyncOutcome::Response(build_servfail_response(&request.to_message()), None);
        };

        if let Some(decision) = self
            .policy
            .evaluate_normalized_domain_with_source(&prepared.cache_key.domain)
        {
            if decision.verdict == Verdict::Block {
                // Only the echoed question is cloned; the owned message is
                // built solely for the SERVFAIL fallback.
                let response = self
                    .policy_block_response(request, &prepared, decision.source, context)
                    .unwrap_or_else(|| build_servfail_response(&request.to_message()));
                let post_ai = self.policy_block_post_work(&prepared, decision.source);
                return CoreSyncOutcome::Response(response, post_ai);
            }
            if decision.verdict == Verdict::Allow {
                // Explicit user allow rules override automatic AI blocking.
                prepared.explicit_allow = true;
            }
        }

        // After the rules, so a blocked name is still answered as blocked. Special-use
        // and classifier-unsupported names continue through existing handling without AI.
        if let Some(response) = self.synthesized_response(request, &prepared) {
            return CoreSyncOutcome::Response(response, None);
        }

        // Like proactive AI, the age check precedes the cache so an answer
        // cached before a domain's date was known cannot bypass the block.
        match self.new_domain_verdict(&prepared) {
            NewDomainVerdict::Block => {
                let response = self
                    .new_domain_block_response(request, &prepared, context)
                    .unwrap_or_else(|| build_servfail_response(&request.to_message()));
                return CoreSyncOutcome::Response(response, None);
            }
            NewDomainVerdict::Pending => return CoreSyncOutcome::Miss(prepared),
            NewDomainVerdict::Allow => {}
        }

        // Proactive AI must precede cache/prefetch/upstream access or a cached
        // answer could bypass AI after proactive mode is enabled. The sync
        // fast path stays free of DB/network I/O: a decision already in memory
        // is applied here, and only a query whose decision needs the store or
        // the classifier moves to the async path.
        let ai_decided = match self.ai_local(&prepared) {
            AiLocal::Pending => return CoreSyncOutcome::Miss(prepared),
            AiLocal::Block(evaluation) => {
                // The gate has just decided about the domain, so its block
                // carries no post-response work.
                let response = self
                    .ai_block_response(request, &prepared, context, &evaluation)
                    .unwrap_or_else(|| build_servfail_response(&request.to_message()));
                return CoreSyncOutcome::Response(response, None);
            }
            AiLocal::Decided => true,
            AiLocal::Clear => false,
        };

        let answer = if prepared.cache_eligible {
            self.probe_cache(&prepared.cache_key)
        } else {
            None
        };
        let Some(answer) = answer else {
            if let Some(held) = self.held_failure_outcome(request, &prepared, context) {
                return held;
            }
            if self.miss_would_fail_fast(&prepared) {
                // Answered or dropped here instead of on a task per query;
                // see `FailFastBudget`.
                let udp = context.is_some_and(|ctx| ctx.protocol == Protocol::Udp);
                if udp && !self.fail_fast_replies.try_take() {
                    self.fail_fast_replies.note_drop();
                    return CoreSyncOutcome::Dropped;
                }
                let servfail = crate::messages::empty_response(
                    request.metadata(),
                    request.first_query(),
                    ResponseCode::ServFail,
                );
                return CoreSyncOutcome::Response(servfail, None);
            }
            return CoreSyncOutcome::Miss(prepared);
        };
        let domain = &prepared.cache_key.domain;
        self.note_client_hint(context, domain, &answer);
        let post_ai = if ai_decided {
            None
        } else {
            self.post_work_for_answer(domain, &answer)
        };
        CoreSyncOutcome::Cached(answer, post_ai)
    }

    /// The answer to a query this resolver makes up itself, whatever an upstream would say:
    /// one for a special-use name, or an `ANY` query. `None` for any other query.
    ///
    /// Special-use names are classified from the already-normalized question, so ordinary
    /// cache hits never clone the client message, and synthesis copies only the question.
    fn synthesized_response<R: RequestView>(
        &self,
        request: &R,
        prepared: &PreparedQuery,
    ) -> Option<Message> {
        let special_use = crate::special_use::classify_special_use_with(
            &prepared.cache_key.domain,
            self.answer_local_names,
        );
        if special_use.is_none() && prepared.qtype != RecordType::ANY {
            return None;
        }
        let Some(question) = request.first_query() else {
            return Some(build_servfail_response(&request.to_message()));
        };
        Some(match special_use {
            Some(kind) => crate::special_use::synthesize_special_use(
                request.metadata(),
                &question,
                request.edns(),
                kind,
                prepared.qtype,
            ),
            None => build_any_response(request.metadata(), question),
        })
    }

    /// Answers a name whose recent failure is still held, without asking
    /// upstream: the stale answer at once (the RFC 8767 §5 failure recheck
    /// timer), or SERVFAIL from the cached failure (RFC 9520 §3.2). `None`
    /// when no failure is held.
    fn held_failure_outcome<R: RequestView>(
        &self,
        request: &R,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
    ) -> Option<CoreSyncOutcome> {
        let key = &prepared.cache_key;
        if !(prepared.cache_eligible && self.response_cache.failure_held(key)) {
            return None;
        }
        Some(match self.response_cache.stale_after_failure(key) {
            Some(stale) => {
                self.note_client_hint(context, &key.domain, &stale);
                let post_ai = self.post_work_for_answer(&key.domain, &stale);
                CoreSyncOutcome::Cached(stale, post_ai)
            }
            None => CoreSyncOutcome::Response(
                build_cached_failure_response(
                    request.metadata(),
                    request.first_query(),
                    request.edns(),
                ),
                None,
            ),
        })
    }

    /// True when the miss path would answer SERVFAIL without trying upstream:
    /// every tier is down with no recovery attempt available, no stale answer
    /// would be served instead, and there is no in-flight fetch to join — the
    /// recovery attempt itself may be resolving this very name.
    fn miss_would_fail_fast(&self, prepared: &PreparedQuery) -> bool {
        self.upstream.read().fails_fast()
            && !(prepared.cache_eligible
                && (self.response_cache.fetch_in_flight(&prepared.cache_key)
                    || self
                        .response_cache
                        .stale_after_failure(&prepared.cache_key)
                        .is_some()))
    }

    /// Probes the cache and reserves near-expiry prefetch, without policy work.
    pub(super) fn probe_cache(&self, cache_key: &CacheKey) -> Option<CachedAnswer> {
        // Stale entries must attempt a foreground refresh before being served.
        // Do not let a background prefetch take ownership of that miss: it has
        // separate admission limits and could delay the foreground request.
        let CacheProbe::Fresh(answer) = self.response_cache.probe(cache_key) else {
            return None;
        };
        if answer.should_prefetch() {
            if let Some(reservation) = self.response_cache.try_reserve_prefetch(cache_key) {
                self.spawn_prefetch(cache_key.clone(), reservation);
            }
        }
        Some(answer)
    }

    /// Returns a policy, special-use, or cached response without upstream I/O.
    ///
    /// A miss hands back the parsed query so [`Self::handle_parsed_miss`] can
    /// finish it without parsing or evaluating policy a second time. `None`
    /// means the query is owed no reply (see `FailFastBudget`).
    #[expect(
        clippy::result_large_err,
        reason = "PreparedQuery carries the inline cache-key domain so a miss can finish without re-parsing; boxing it would heap-allocate on every miss"
    )]
    pub(crate) fn try_handle_parsed_sync(
        &self,
        request: &MessageRequest,
        context: Option<DnsQueryContext>,
    ) -> std::result::Result<Option<PreparedResponse>, PreparedQuery> {
        match self.process_core(request, context) {
            CoreSyncOutcome::Response(message, post_ai) => {
                Ok(Some(prepare_uncached_message(message, post_ai)))
            }
            CoreSyncOutcome::Cached(answer, post_ai) => {
                Ok(Some(prepare_cached_message(answer, request, post_ai)))
            }
            CoreSyncOutcome::Miss(prepared) => Err(prepared),
            CoreSyncOutcome::Dropped => Ok(None),
        }
    }

    /// Answers a policy block, reporting the rule or blocklists that matched.
    pub(super) fn policy_block_response<R: RequestView>(
        &self,
        request: &R,
        prepared: &PreparedQuery,
        source: Option<DomainBlockSource>,
        context: Option<DnsQueryContext>,
    ) -> Option<Message> {
        let domain = &prepared.cache_key.domain;
        self.block_response(
            request,
            domain,
            prepared.qtype,
            source.map(DomainBlockSource::as_str),
            context,
            || {
                let matching = if source == Some(DomainBlockSource::Blocklist) {
                    self.policy.matching_normalized_blocklists(domain)
                } else {
                    Vec::new()
                };
                source
                    .map(|source| source.reported_blocklist_names(matching))
                    .unwrap_or_default()
            },
        )
    }

    /// Post-response classification for a policy block. Only blocklist
    /// matches are classified: the blocked response is sent first, and the
    /// domain is classified in the background only if no decision exists. A
    /// user's own rule needs no classification.
    fn policy_block_post_work(
        &self,
        prepared: &PreparedQuery,
        source: Option<DomainBlockSource>,
    ) -> Option<PostResponseWork> {
        (source == Some(DomainBlockSource::Blocklist))
            .then(|| self.post_work_for_domain_key(&prepared.cache_key.domain, true))
            .flatten()
    }

    /// Settles an asynchronous gate's decision against policy as it stands
    /// once the gate is done waiting.
    ///
    /// Policy may change while a gate awaits a lookup, and a rule added
    /// meanwhile wins: a new allow resolves normally (`None`), and a new block
    /// keeps its own attribution and post-response work, as it would have
    /// without the gate. Without a matching rule, `gate_block` decides; a
    /// gate's own block carries no post-response work, because the gate has
    /// just decided about the domain.
    pub(super) fn recheck_policy_after_gate(
        &self,
        request: &Message,
        prepared: &PreparedQuery,
        context: Option<DnsQueryContext>,
        gate_block: impl FnOnce() -> Option<Message>,
    ) -> Option<GateBlock> {
        let Some(decision) = self
            .policy
            .evaluate_normalized_domain_with_source(&prepared.cache_key.domain)
        else {
            return gate_block().map(|block| (block, None));
        };
        match decision.verdict {
            Verdict::Allow => None,
            // A block that cannot be built still blocks: `None` here would
            // mean "resolve upstream".
            Verdict::Block => Some((
                self.policy_block_response(request, prepared, decision.source, context)
                    .unwrap_or_else(|| build_servfail_response(request)),
                self.policy_block_post_work(prepared, decision.source),
            )),
        }
    }

    pub(super) fn block_response<R, F>(
        &self,
        request: &R,
        normalized: &str,
        qtype: RecordType,
        source: Option<&'static str>,
        context: Option<DnsQueryContext>,
        resolve_blocklist_names: F,
    ) -> Option<Message>
    where
        R: RequestView,
        F: FnOnce() -> Vec<String>,
    {
        self.block_signals.signal_block(
            normalized,
            qtype,
            source,
            self.block_mode,
            context,
            resolve_blocklist_names,
        );
        let question = request.first_query()?;
        let response = build_block_response(
            request.metadata(),
            question,
            request.edns(),
            self.block_mode,
            self.custom_block_ip,
        )
        .ok()?;
        if matches!(
            self.block_mode,
            BlockResponseMode::Sinkhole | BlockResponseMode::Custom
        ) {
            self.record_block_resolution(normalized, &response);
        }
        Some(response)
    }
}
