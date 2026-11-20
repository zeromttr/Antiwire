//! One transport tier: a Hickory pool, whether it is usable, and its
//! cold-start gate.
//!
//! A tier is down after [`DOH_ENDPOINT_FAILURE_THRESHOLD`] consecutive
//! transport failures. While down it is skipped, except by one recovery
//! attempt at a time, spaced [`DNS_UPSTREAM_RECOVERY_INTERVAL`] apart; the
//! first recovery attempt may start as soon as the tier goes down. Server
//! choice inside a tier is Hickory's.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{DnsRequest, DnsRequestOptions, Message, MessageType};
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::net::{NetError, RetryDnsHandle};
use hickory_resolver::{NameServerPool, PoolContext};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, SemaphorePermit};
use tracing::{debug, info, warn};

use antiwire_tuning::{DNS_UPSTREAM_RECOVERY_INTERVAL, DOH_ENDPOINT_FAILURE_THRESHOLD};

use super::endpoint::UpstreamEndpoint;
use super::error_kind::{
    empty_answer_for_error, is_benign_empty_answer, is_dns_level_error, upstream_error_kind,
};
use super::exchange::{Turn, UpstreamAnswer};
use super::runtime::UpstreamRuntime;
use super::{resolve_error_msg, transport_tag, MAX_IN_FLIGHT_PER_TIER};
use crate::settings::DnsProtocol;

pub(super) struct Tier {
    /// Transport and endpoints, for logs.
    pub(super) label: Arc<str>,
    handle: RetryDnsHandle<NameServerPool<UpstreamRuntime>>,
    request_options: DnsRequestOptions,
    pub(super) health: TierHealth,
    /// Bounds sends into Hickory's smaller per-connection queues. Once an
    /// attempt is sent, the permit stays with it even if its caller times out
    /// or a fallback wins.
    in_flight: Semaphore,
    /// `None` for UDP, which has no connection to stampede.
    cold_start: Option<ColdStart>,
    /// Whether answers arrive over an encrypted, authenticated transport,
    /// the only kind whose AD bit can be trusted (RFC 4035 §4.9.3).
    encrypted: bool,
}

/// Whether an attempt reached a server, for tier health.
#[derive(Clone, Copy)]
pub(super) enum Reach {
    /// A server answered, even with an error response.
    Reached,
    /// No server could be reached.
    Unreachable,
    /// Never sent, so it says nothing about the tier.
    NotSent,
}

impl Tier {
    pub(super) fn new(
        endpoints: &[UpstreamEndpoint],
        pool_context: &Arc<PoolContext>,
        provider: &UpstreamRuntime,
        retry_attempts: usize,
        request_options: DnsRequestOptions,
    ) -> Self {
        let protocol = endpoints
            .first()
            .map_or(DnsProtocol::Udp, |endpoint| endpoint.protocol);
        let label = format!(
            "{} {}",
            transport_tag(protocol),
            endpoints
                .iter()
                .map(UpstreamEndpoint::label)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let pool = NameServerPool::from_config(
            endpoints
                .iter()
                .map(UpstreamEndpoint::to_name_server_config),
            Arc::clone(pool_context),
            provider.clone(),
        );
        Self {
            label: Arc::from(label),
            handle: RetryDnsHandle::new(pool, retry_attempts),
            request_options,
            health: TierHealth::new(),
            in_flight: Semaphore::new(MAX_IN_FLIGHT_PER_TIER),
            cold_start: (protocol != DnsProtocol::Udp).then(ColdStart::new),
            encrypted: matches!(
                protocol,
                DnsProtocol::Tls | DnsProtocol::Quic | DnsProtocol::Https | DnsProtocol::H3
            ),
        }
    }

    /// Sends `request` through this tier's pool once it is `turn`'s turn.
    /// `recovering` says the attempt owns the recovery of a tier that is down.
    pub(super) async fn send(
        &self,
        request: &Message,
        turn: &Turn,
        recovering: bool,
    ) -> (Result<UpstreamAnswer, NetError>, Reach) {
        // The outer admission budget bounds exchanges across all tiers, not
        // requests on one pooled connection. Queue excess work here, and
        // refuse it locally once its wait runs out, before Hickory turns its
        // Busy into an ambiguous NoConnections failure.
        let Some(_turn) = self.wait_for(turn).await else {
            return (
                Err(resolve_error_msg(crate::upstream::TIER_BUSY)),
                Reach::NotSent,
            );
        };
        // The tier may have gone down during the wait. A down tier is asked
        // by its recovery attempt alone: anything else sent to it would be a
        // second, unspaced recovery attempt.
        if !recovering && self.health.is_down() {
            return (
                Err(resolve_error_msg(crate::upstream::TIER_WENT_DOWN)),
                Reach::NotSent,
            );
        }

        let started = Instant::now();
        let mut query = request.clone();
        query.metadata.message_type = MessageType::Query;
        // RFC 6840 §5.7: AD asks the upstream to report validation. Whether a
        // client sees it is decided per client when the answer is served, so
        // the cached answer keeps it for every client that asks.
        query.metadata.authentic_data = true;
        if let Some(edns) = query.edns.as_mut() {
            edns.options_mut()
                .options
                .retain(|(code, _)| crate::upstream::forwards_edns_option(*code));
        }
        let result = self
            .handle
            .send(DnsRequest::new(query, self.request_options))
            .first_answer()
            .await;
        let elapsed = started.elapsed();
        match result {
            Ok(response) => {
                let (mut message, wire) = response.into_parts();
                message.metadata.id = request.metadata.id;
                // Over plain UDP or TCP anyone on the path can set AD.
                message.metadata.authentic_data &= self.encrypted;
                if let Some(edns) = message.edns.as_mut() {
                    edns.options_mut()
                        .options
                        .retain(|(code, _)| !crate::upstream::is_upstream_transport_option(*code));
                }
                (
                    Ok(UpstreamAnswer {
                        message,
                        encoded_len: Some(wire.len()),
                    }),
                    Reach::Reached,
                )
            }
            // Hickory reports NXDOMAIN and empty answers as errors.
            Err(error) if is_benign_empty_answer(&error) => (
                Ok(UpstreamAnswer {
                    message: empty_answer_for_error(request, &error),
                    encoded_len: None,
                }),
                Reach::Reached,
            ),
            Err(error) => {
                debug!(
                    tier = %self.label,
                    elapsed_ms = elapsed.as_millis(),
                    error_kind = upstream_error_kind(&error),
                    %error,
                    "dns upstream tier attempt failed"
                );
                let reach = if is_dns_level_error(&error) {
                    Reach::Reached
                } else {
                    Reach::Unreachable
                };
                (Err(error), reach)
            }
        }
    }

    /// Waits until an attempt may be sent: behind the attempt that is opening
    /// the tier's connection, if one is, and then for an in-flight slot.
    /// `None` when the turn does not come.
    ///
    /// Nothing has been sent while this waits, so it ends with `turn`'s
    /// exchange: an attempt nobody is waiting for is not worth a query, and
    /// must not go on holding what admitted its exchange. The wait behind a
    /// connection has no other limit, because the connection may be all that
    /// stands between a client and its answer. The wait for a slot also ends
    /// at the turn's deadline.
    async fn wait_for(
        &self,
        turn: &Turn,
    ) -> Option<(Option<OwnedSemaphorePermit>, SemaphorePermit<'_>)> {
        let wait = async {
            let opening = match &self.cold_start {
                Some(gate) => gate.admit().await,
                None => None,
            };
            let slot = tokio::time::timeout_at(turn.slot_deadline, self.in_flight.acquire())
                .await
                .ok()?
                .ok()?;
            Some((opening, slot))
        };
        tokio::select! {
            biased;
            () = turn.exchange_over.cancelled() => None,
            waited = wait => waited,
        }
    }

    /// Whether another attempt is opening this tier's connection, so one
    /// started now would wait behind it.
    pub(super) fn is_opening(&self) -> bool {
        self.cold_start.as_ref().is_some_and(ColdStart::is_held)
    }

    /// Applies one attempt's outcome, settling `recovery` if it held one.
    pub(super) fn record(&self, reach: Reach, recovery: Option<RecoveryClaim>) {
        match reach {
            Reach::Reached => {
                if let Some(gate) = &self.cold_start {
                    gate.mark_ready();
                }
                if self.health.note_success() {
                    info!(tier = %self.label, "dns upstream tier recovered");
                }
            }
            Reach::Unreachable => {
                if self.health.note_failure(recovery.is_some()) {
                    if let Some(gate) = &self.cold_start {
                        gate.rearm();
                    }
                    warn!(
                        tier = %self.label,
                        "dns upstream tier is down; skipping it until a recovery attempt succeeds"
                    );
                }
            }
            Reach::NotSent => {}
        }
        if let Some(mut claim) = recovery {
            claim.settled = !matches!(reach, Reach::NotSent);
        }
    }
}

/// Consecutive-failure tracking for one tier.
pub(super) struct TierHealth {
    epoch: Instant,
    failures: AtomicU32,
    down: AtomicBool,
    recovering: AtomicBool,
    /// Earliest recovery attempt, in milliseconds since `epoch`.
    retry_at_ms: AtomicU64,
}

/// Whether an exchange may use a tier.
pub(super) enum Admission {
    Up,
    /// Down, and this exchange owns the tier's one recovery attempt.
    Recovery(RecoveryClaim),
    Skip,
}

impl TierHealth {
    fn new() -> Self {
        Self {
            epoch: Instant::now(),
            failures: AtomicU32::new(0),
            down: AtomicBool::new(false),
            recovering: AtomicBool::new(false),
            retry_at_ms: AtomicU64::new(0),
        }
    }

    pub(super) fn is_down(&self) -> bool {
        self.down.load(Ordering::Acquire)
    }

    /// Whether the tier has failed since it last answered.
    pub(super) fn has_failed(&self) -> bool {
        self.failures.load(Ordering::Acquire) > 0
    }

    #[cfg(test)]
    pub(super) fn is_recovering(&self) -> bool {
        self.recovering.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn consecutive_failures(&self) -> u32 {
        self.failures.load(Ordering::Acquire)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// True when [`Self::admit`] would skip this tier right now: it is down,
    /// and its next recovery attempt is either not due or already running.
    pub(super) fn skips_now(&self) -> bool {
        self.is_down()
            && (self.now_ms() < self.retry_at_ms.load(Ordering::Acquire)
                || self.recovering.load(Ordering::Acquire))
    }

    pub(super) fn admit(tier: &Arc<Tier>) -> Admission {
        let health = &tier.health;
        if !health.is_down() {
            return Admission::Up;
        }
        if health.now_ms() < health.retry_at_ms.load(Ordering::Acquire) {
            return Admission::Skip;
        }
        if health
            .recovering
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Admission::Skip;
        }
        Admission::Recovery(RecoveryClaim {
            tier: Arc::clone(tier),
            settled: false,
        })
    }

    /// Returns true when this success brought the tier back up.
    fn note_success(&self) -> bool {
        self.failures.store(0, Ordering::Release);
        self.recovering.store(false, Ordering::Release);
        self.down.swap(false, Ordering::AcqRel)
    }

    /// Returns true when this failure took the tier down.
    ///
    /// While the tier is down only the recovery owner's failure counts; an
    /// attempt admitted before the tier went down says nothing new.
    fn note_failure(&self, recovery_owner: bool) -> bool {
        let threshold = u32::try_from(DOH_ENDPOINT_FAILURE_THRESHOLD)
            .unwrap_or(3)
            .max(1);
        if self.is_down() {
            if recovery_owner {
                // Wait out the interval before the next recovery attempt.
                self.schedule_retry();
                self.recovering.store(false, Ordering::Release);
            }
            return false;
        }
        let failures = self.failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures < threshold {
            return false;
        }
        // The first recovery attempt may start at once; the interval only
        // spaces out attempts that keep failing.
        self.retry_at_ms.store(0, Ordering::Release);
        !self.down.swap(true, Ordering::AcqRel)
    }

    fn schedule_retry(&self) {
        let interval = u64::try_from(DNS_UPSTREAM_RECOVERY_INTERVAL.as_millis()).unwrap_or(1_000);
        self.retry_at_ms
            .store(self.now_ms().saturating_add(interval), Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn force_down(&self) {
        self.retry_at_ms.store(0, Ordering::Release);
        self.recovering.store(false, Ordering::Release);
        self.down.store(true, Ordering::Release);
    }
}

/// Ownership of a down tier's one recovery attempt.
///
/// Settled by [`Tier::record`]. Dropped unsettled — the attempt never sent a
/// query — it releases the claim without spending the retry interval.
pub(super) struct RecoveryClaim {
    tier: Arc<Tier>,
    settled: bool,
}

impl Drop for RecoveryClaim {
    fn drop(&mut self) {
        if !self.settled {
            self.tier.health.recovering.store(false, Ordering::Release);
        }
    }
}

/// Test hook holding every tier's recovery claim.
#[cfg(test)]
pub(crate) struct RecoveryHold {
    _claims: Vec<RecoveryClaim>,
}

#[cfg(test)]
impl RecoveryHold {
    pub(super) fn claim_all(tiers: &[Arc<Tier>]) -> Option<Self> {
        let claims = tiers
            .iter()
            .map(|tier| match TierHealth::admit(tier) {
                Admission::Recovery(claim) => Some(claim),
                Admission::Up | Admission::Skip => None,
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { _claims: claims })
    }
}

/// Lets one attempt at a time through a tier that has no connection yet.
///
/// Hickory 0.26 opens a new connection for every request that arrives while
/// none exists, so a burst after startup or a network change would otherwise
/// start one TLS or HTTP/2 handshake per query. Once an attempt reaches a
/// server the gate opens for everyone; it closes again when the tier goes down.
struct ColdStart {
    ready: AtomicBool,
    slot: Arc<Semaphore>,
}

impl ColdStart {
    fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            slot: Arc::new(Semaphore::new(1)),
        }
    }

    /// Waits for the gate. `None` means the tier is warm. The caller bounds
    /// the wait.
    async fn admit(&self) -> Option<OwnedSemaphorePermit> {
        if self.ready.load(Ordering::Acquire) {
            return None;
        }
        // The gate is never closed, so the wait only ends with a permit.
        let permit = Arc::clone(&self.slot).acquire_owned().await.ok()?;
        (!self.ready.load(Ordering::Acquire)).then_some(permit)
    }

    /// Whether the tier is cold and an attempt holds the gate.
    fn is_held(&self) -> bool {
        !self.ready.load(Ordering::Acquire) && self.slot.available_permits() == 0
    }

    fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    fn rearm(&self) {
        self.ready.store(false, Ordering::Release);
    }
}
