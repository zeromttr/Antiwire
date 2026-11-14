//! Query orchestration: policy, response cache, and upstream admission.
//!
//! - `request`: validating and parsing an incoming query.
//! - `local`: answers that need no upstream I/O.
//! - `miss`: the asynchronous miss path and its upstream fetch.
//! - `prefetch`: background refresh of entries nearing expiry.
//! - `ai`: the AI gate and post-response classification work.
//! - `hints`: reporting answered addresses to the flow tracker.
//! - `response`: the parsed response handed to hickory-server.

mod ai;
mod hints;
mod local;
mod miss;
mod new_domain;
mod prefetch;
mod request;
mod response;
#[cfg(test)]
mod tests;

use std::sync::Arc;

use antiwire_policy::PolicyEngine;
use antiwire_store::Store;
use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::ai::AiCoordinator;
use crate::block::{BlockResponseMode, BlockSignalLogger, DnsBlockSink};
use crate::new_domain::{NewDomainGuard, RegistrationDates};
use crate::provider_block::ProviderFilter;
use crate::response_cache::ResponseCache;
use crate::settings::{DnsConfig, DnsProtocol};
use crate::upstream::{build_upstream_dns, SharedUpstreamAdmission, UpstreamAdmission};
use crate::{DnsError, Result};

use self::local::FailFastBudget;
pub(crate) use self::request::PreparedQuery;
#[cfg(test)]
pub(crate) use self::response::prepare_uncached_message;
pub(crate) use self::response::PreparedResponse;

/// Orchestrates DNS query handling with cache fast path and bounded upstream work.
pub(crate) struct QueryEngine<P> {
    policy: P,
    ai: RwLock<Option<Arc<AiCoordinator>>>,
    response_cache: Arc<ResponseCache>,
    block_mode: BlockResponseMode,
    custom_block_ip: Option<std::net::IpAddr>,
    rebinding_protection_enabled: bool,
    /// Off forwards `.local` names upstream instead of answering them locally.
    answer_local_names: bool,
    /// Blocks recently registered domains when the settings ask for it.
    new_domains: Option<NewDomainGuard>,
    /// Shared through an `Arc` so detached prefetch tasks can re-acquire the
    /// current pool together with the generation on every retry attempt,
    /// instead of reusing the pool captured when they were spawned.
    upstream: Arc<RwLock<SharedUpstreamAdmission>>,
    upstream_protocol: DnsProtocol,
    upstream_endpoints: RwLock<Vec<String>>,
    /// Derived from `upstream_endpoints`, and replaced with them.
    provider_filter: RwLock<ProviderFilter>,
    block_signals: Arc<BlockSignalLogger>,
    hint_sink: RwLock<Option<Arc<dyn crate::DnsHintSink>>>,
    /// Finishes hint attribution off the reply path; see `note_client_hint`.
    owner_worker: crate::owner_worker::OwnerWorker,
    prefetch_tasks: TaskTracker,
    prefetch_cancel: CancellationToken,
    fail_fast_replies: FailFastBudget,
    /// Configured upstreams that were skipped, and why.
    upstream_config_warnings: Vec<String>,
}

/// What an engine works with besides its policy and settings. Each is
/// optional: tests and benchmarks give only what they exercise.
#[derive(Default)]
pub(crate) struct EngineServices {
    /// Saved AI decisions; with it the engine starts the AI coordinator the
    /// settings ask for.
    pub(crate) store: Option<Arc<Store>>,
    /// Receives every blocked query.
    pub(crate) block_sink: Option<Arc<dyn DnsBlockSink>>,
    /// Needed to block newly registered domains.
    pub(crate) registration_dates: Option<RegistrationDates>,
}

impl<P> QueryEngine<P>
where
    P: PolicyEngine + Send + Sync,
{
    /// Builds the engine. With a store, it also starts the AI coordinator the
    /// saved settings ask for. Skipped upstreams are kept for the caller to
    /// report; see [`Self::upstream_config_warnings`].
    pub(crate) fn try_new(policy: P, config: &DnsConfig, services: EngineServices) -> Result<Self> {
        let EngineServices {
            store,
            block_sink,
            registration_dates,
        } = services;
        let upstream_dns = Arc::new(build_upstream_dns(config.protocol, &config.upstreams)?);
        let upstream_config_warnings = upstream_dns.config_warnings().to_vec();
        let upstream = UpstreamAdmission::new(upstream_dns);

        let engine = Self {
            policy,
            ai: RwLock::new(None),
            response_cache: Arc::new(ResponseCache::new()),
            block_mode: config.block_mode,
            custom_block_ip: config.custom_block_ip,
            rebinding_protection_enabled: config.rebinding_protection_enabled,
            answer_local_names: config.answer_local_names,
            new_domains: config.new_domain_max_age_days.and_then(|days| {
                if registration_dates.is_none() {
                    tracing::warn!("no registration dates; new domain blocking is off");
                }
                registration_dates.map(|dates| NewDomainGuard::new(days, dates.0))
            }),
            upstream: Arc::new(RwLock::new(Arc::new(upstream))),
            upstream_protocol: config.protocol,
            upstream_endpoints: RwLock::new(config.upstreams.clone()),
            provider_filter: RwLock::new(ProviderFilter::for_endpoints(&config.upstreams)),
            block_signals: Arc::new(BlockSignalLogger::new(block_sink)),
            fail_fast_replies: FailFastBudget::new(),
            hint_sink: RwLock::new(None),
            owner_worker: crate::owner_worker::OwnerWorker::default(),
            prefetch_tasks: TaskTracker::new(),
            prefetch_cancel: CancellationToken::new(),
            upstream_config_warnings,
        };
        if let Some(store) = store {
            if let Some(ai) = crate::ai_support::build_coordinator_from_store(store) {
                engine.set_ai(Some(ai));
            }
        }
        Ok(engine)
    }

    /// Configured upstreams that were skipped when the engine was built.
    pub(crate) fn upstream_config_warnings(&self) -> &[String] {
        &self.upstream_config_warnings
    }

    #[cfg(test)]
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "tests build the config inline and hand it over"
    )]
    pub(crate) fn new(policy: P, config: DnsConfig) -> Self {
        Self::try_new(policy, &config, EngineServices::default())
            .expect("query engine upstream resolver")
    }

    /// Replaces the new-domain guard, for tests that supply registration dates.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_new_domain_guard(mut self, guard: NewDomainGuard) -> Self {
        self.new_domains = Some(guard);
        self
    }

    /// Publishes updated AI configuration without restarting the engine.
    pub(crate) fn update_ai_config(
        &self,
        store: &Arc<Store>,
        runtime: crate::ai_support::AiRuntimeConfig,
    ) {
        let crate::ai_support::AiRuntimeConfig {
            mut policy,
            classifier,
            bootstrap_host,
        } = runtime;
        if let Some(ai) = self.ai_coordinator() {
            // The coordinator owns the generation. Passing a fresh snapshot
            // invalidates all work started under the previous configuration.
            policy.generation = ai.generation();
            ai.update_config(&policy, classifier, bootstrap_host);
        } else if policy.enabled {
            // Keep a coordinator alive even when the provider client is
            // unavailable so saved decisions remain enforceable. Unknown
            // domains fail open until a valid client is supplied by a later
            // settings update.
            let ai = AiCoordinator::new(Arc::clone(store), classifier, &policy, bootstrap_host);
            self.set_ai(Some(ai));
        }
    }

    /// Bounded async drain of AI background work before the blocking teardown.
    pub(crate) async fn shutdown_async(&self) {
        if let Some(ai) = self.ai_coordinator() {
            ai.shutdown().await;
        }
    }

    #[must_use]
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn response_cache(&self) -> &Arc<ResponseCache> {
        &self.response_cache
    }

    pub(crate) fn set_hint_sink(&self, sink: Arc<dyn crate::DnsHintSink>) {
        *self.hint_sink.write() = Some(sink);
    }

    /// Attaches the shared AI coordinator (built from store settings).
    pub(crate) fn set_ai(&self, ai: Option<Arc<AiCoordinator>>) {
        *self.ai.write() = ai;
    }

    /// Shared AI coordinator, if configured.
    #[must_use]
    pub(crate) fn ai_coordinator(&self) -> Option<Arc<AiCoordinator>> {
        self.ai.read().clone()
    }

    /// Stops the block-signal and attribution workers and cancels remaining
    /// AI work.
    ///
    /// In-flight fetch futures share the worker, so relying on `Drop` would
    /// leave the join to whichever holder happens to go last — possibly a
    /// cancelled request on a runtime thread, where `Drop` cannot wait.
    /// Blocks for the whole drain; call it from a blocking thread.
    pub(crate) fn shutdown_blocking(&self) {
        self.block_signals.shutdown();
        self.owner_worker.shutdown();
        // Cancel remaining AI work synchronously; the async drain (with its
        // bounded timeout) runs in `QueryEngine::shutdown_async` before this.
        if let Some(ai) = self.ai.read().clone() {
            ai.shutdown_cancel();
        }
    }

    /// Rebuilds transport pools and endpoint health after the active network changes.
    pub(crate) async fn reset_after_network_change(&self) -> Result<()> {
        let protocol = self.upstream_protocol;
        let endpoints = self.upstream_endpoints.read().clone();
        let rebuilt =
            match tokio::task::spawn_blocking(move || build_upstream_dns(protocol, &endpoints))
                .await
            {
                Ok(Ok(rebuilt)) => rebuilt,
                Ok(Err(error)) => {
                    self.response_cache.bump_generation();
                    return Err(error);
                }
                Err(error) => {
                    self.response_cache.bump_generation();
                    return Err(DnsError::Upstream(format!(
                        "upstream rebuild task failed: {error}"
                    )));
                }
            };
        let rebuilt = Arc::new(rebuilt);
        let admission = Arc::new(UpstreamAdmission::new(rebuilt));

        // Swap first and then retire the cache generation. The miss path reads
        // those in the opposite order, so it cannot pair an old pool with the
        // new generation and repopulate the cache from the previous network.
        *self.upstream.write() = admission;
        self.response_cache.bump_generation();
        Ok(())
    }

    /// Test hook: mark every upstream tier down so degraded-mode
    /// (serve-stale-first) paths can be exercised without real network
    /// failures.
    #[cfg(test)]
    pub(crate) fn mark_upstream_degraded_for_test(&self) {
        self.upstream().inner().mark_all_endpoints_failed();
    }

    #[cfg(test)]
    pub(crate) fn hold_recovery_for_test(&self) -> Option<crate::upstream::RecoveryHold> {
        self.upstream().inner().hold_recovery_for_test()
    }

    #[cfg(test)]
    pub(crate) fn recovery_occupied_for_test(&self) -> bool {
        self.upstream().inner().recovery_occupied_for_test()
    }

    /// Test hook: rebuild the pool from new endpoints on the next reset.
    #[cfg(test)]
    pub(crate) fn set_upstream_endpoints_for_test(&self, endpoints: Vec<String>) {
        *self.provider_filter.write() = ProviderFilter::for_endpoints(&endpoints);
        *self.upstream_endpoints.write() = endpoints;
    }

    /// Acquires the upstream pool paired with the generation it is valid for.
    ///
    /// Reads the generation first and the pool second: [`Self::reset_after_network_change`]
    /// swaps the pool first and bumps the generation second, so this order can
    /// pair a new pool with an old generation (harmless — the attempt is
    /// discarded and retried) but never an old pool with a new generation
    /// (which would admit a retired-network answer under the live generation).
    /// Every retry attempt must call this again rather than reusing an earlier
    /// pair.
    fn current_generation_and_upstream(&self) -> (u64, SharedUpstreamAdmission) {
        let generation = self.response_cache.current_generation();
        (generation, self.upstream())
    }

    /// The current upstream pool.
    fn upstream(&self) -> SharedUpstreamAdmission {
        Arc::clone(&self.upstream.read())
    }
}

impl<P> Drop for QueryEngine<P> {
    fn drop(&mut self) {
        self.prefetch_cancel.cancel();
        self.prefetch_tasks.close();
    }
}
