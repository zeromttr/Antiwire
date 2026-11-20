//! Tries a query's tiers in order, starting the next one early when a tier is
//! slow to answer.

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FuturesUnordered, StreamExt};
use hickory_proto::op::Message;
use hickory_resolver::net::NetError;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use antiwire_tuning::{
    DNS_TRANSPORT_TIMEOUT, DNS_UPSTREAM_ADMISSION_TIMEOUT, DOH_FORWARD_TIMEOUT, DOH_HEDGE_DELAY,
};

use super::tier::{Admission, RecoveryClaim, Tier, TierHealth};
use super::{resolve_error_msg, UpstreamDns};

/// Parsed answer plus its original encoded size.
pub(crate) struct UpstreamAnswer {
    pub(crate) message: Message,
    pub(crate) encoded_len: Option<usize>,
}

type Admitted = (Arc<Tier>, Option<RecoveryClaim>);

/// What an attempt that has not been sent yet waits within.
#[derive(Clone)]
pub(super) struct Turn {
    /// The latest an attempt may queue for one of a tier's in-flight slots.
    pub(super) slot_deadline: Instant,
    /// Cancelled when the exchange ends: answered, failed, out of time, or
    /// dropped by its caller.
    pub(super) exchange_over: CancellationToken,
}

/// Held by every attempt an exchange starts, so it is released only when the
/// last of them finishes, including attempts that outlive the exchange.
pub(crate) type AttemptGuard = Arc<dyn std::any::Any + Send + Sync>;

impl UpstreamDns {
    /// Forwards `request` upstream.
    ///
    /// `budget` is the time left on the client query deadline, capped at
    /// [`DOH_FORWARD_TIMEOUT`], which `None` uses. With every tier down and
    /// its recovery already under way, this fails at once.
    pub(crate) async fn exchange(
        &self,
        request: &Message,
        budget: Option<Duration>,
    ) -> Result<UpstreamAnswer, NetError> {
        self.exchange_guarded(request, budget, None).await
    }

    /// [`Self::exchange`], with `guard` kept alive by every attempt it starts.
    pub(crate) async fn exchange_guarded(
        &self,
        request: &Message,
        budget: Option<Duration>,
        guard: Option<AttemptGuard>,
    ) -> Result<UpstreamAnswer, NetError> {
        let exchange_id = self.next_exchange_id.fetch_add(1, Ordering::Relaxed);
        let admitted: Vec<Admitted> = self
            .tiers
            .iter()
            .filter_map(|tier| match TierHealth::admit(tier) {
                Admission::Up => Some((Arc::clone(tier), None)),
                Admission::Recovery(claim) => Some((Arc::clone(tier), Some(claim))),
                Admission::Skip => None,
            })
            .collect();
        if admitted.is_empty() {
            debug!(
                protocol = self.protocol,
                exchange_id, "every dns upstream tier is down and already recovering"
            );
            return Err(resolve_error_msg(crate::upstream::EVERY_TIER_DOWN));
        }

        let limit = budget
            .unwrap_or(DOH_FORWARD_TIMEOUT)
            .min(DOH_FORWARD_TIMEOUT);
        let turn = Turn {
            slot_deadline: Instant::now() + slot_wait(budget),
            exchange_over: CancellationToken::new(),
        };
        // However this exchange ends, its attempts still waiting to be sent
        // stop waiting.
        let _over = turn.exchange_over.clone().drop_guard();
        let attempts = race(admitted, request, guard.as_ref(), &turn);
        let Ok(result) = tokio::time::timeout(limit, attempts).await else {
            debug!(
                protocol = self.protocol,
                exchange_id,
                limit_ms = limit.as_millis(),
                "dns upstream exchange ran out of time"
            );
            return Err(NetError::Timeout);
        };
        if let Err(error) = &result {
            debug!(
                protocol = self.protocol,
                exchange_id,
                %error,
                "dns upstream exchange failed"
            );
        }
        result
    }
}

/// How long an exchange's attempts may queue for one of a tier's in-flight
/// slots.
///
/// With a client deadline, an attempt waits for as long as one transport
/// attempt still fits in what is left of it. A burst of uncached names that
/// outruns a tier is then answered a little late instead of refused: slots
/// turn over in one upstream round trip, far sooner than the deadline. Work
/// with no deadline is a refresh nobody is waiting for, so it gets only the
/// short wait and does not queue ahead of clients.
fn slot_wait(budget: Option<Duration>) -> Duration {
    budget.map_or(DNS_UPSTREAM_ADMISSION_TIMEOUT, |budget| {
        budget
            .min(DOH_FORWARD_TIMEOUT)
            .saturating_sub(DNS_TRANSPORT_TIMEOUT)
            .max(DNS_UPSTREAM_ADMISSION_TIMEOUT)
    })
}

/// Starts the first tier, then each next one when the tiers before it have
/// failed or none has answered within its [`head_start`]. The first answer
/// wins.
///
/// Attempts run on their own tasks, and one that has been sent is never
/// cancelled. If it loses the race, or outlives the caller's deadline, it
/// still finishes and records whether its tier was reachable. Without that, a
/// primary tier that always loses to its fallback — port 853 blocked, say —
/// would never be marked down, and every query would keep paying the hedge
/// delay for it. An attempt still waiting to be sent says nothing about its
/// tier, and stops when the exchange ends: see [`Turn`]. Each attempt holds
/// `guard`, so whatever admitted the exchange keeps counting it.
async fn race(
    admitted: Vec<Admitted>,
    request: &Message,
    guard: Option<&AttemptGuard>,
    turn: &Turn,
) -> Result<UpstreamAnswer, NetError> {
    let mut tiers = Tiers {
        waiting: admitted.into_iter(),
        running: FuturesUnordered::new(),
        request,
        guard,
        turn,
    };
    let hedge = tokio::time::sleep(DOH_HEDGE_DELAY);
    tokio::pin!(hedge);
    tiers.start_next(hedge.as_mut());
    let mut last_error;

    loop {
        tokio::select! {
            Some(joined) = tiers.running.next() => {
                match joined {
                    Ok(Ok(answer)) => return Ok(answer),
                    Ok(Err(error)) => last_error = error,
                    Err(error) => {
                        last_error =
                            resolve_error_msg(format!("upstream attempt task failed: {error}"));
                    }
                }
                if tiers.running.is_empty() {
                    // Nothing left in flight: try the next tier now rather
                    // than wait out the hedge delay.
                    if tiers.waiting.len() == 0 {
                        return Err(last_error);
                    }
                    tiers.start_next(hedge.as_mut());
                }
            }
            () = &mut hedge, if tiers.waiting.len() > 0 => tiers.start_next(hedge.as_mut()),
        }
    }
}

type Attempt = JoinHandle<Result<UpstreamAnswer, NetError>>;

/// One exchange's tiers: those still to be asked, and the attempts running.
struct Tiers<'a> {
    waiting: std::vec::IntoIter<Admitted>,
    running: FuturesUnordered<Attempt>,
    request: &'a Message,
    guard: Option<&'a AttemptGuard>,
    turn: &'a Turn,
}

impl Tiers<'_> {
    /// Starts the next tier, and each one after it at once while the tier
    /// before gets no [`head_start`]. Sets `hedge` to when the tier after the
    /// last one started is due.
    fn start_next(&mut self, mut hedge: Pin<&mut Sleep>) {
        for (tier, recovery) in self.waiting.by_ref() {
            let head_start = head_start(&tier);
            self.running
                .push(start(tier, recovery, self.request, self.guard, self.turn));
            if !head_start.is_zero() {
                hedge.as_mut().reset(Instant::now() + head_start);
                return;
            }
        }
    }
}

/// Starts the attempt on `tier`.
fn start(
    tier: Arc<Tier>,
    recovery: Option<RecoveryClaim>,
    request: &Message,
    guard: Option<&AttemptGuard>,
    turn: &Turn,
) -> Attempt {
    let request = request.clone();
    let guard = guard.cloned();
    let turn = turn.clone();
    tokio::spawn(async move {
        let _guard = guard;
        let (result, reach) = tier.send(&request, &turn, recovery.is_some()).await;
        tier.record(reach, recovery);
        result
    })
}

/// How long a tier has to answer before the tier after it is asked as well.
///
/// A tier whose connection another attempt is opening gets none. This
/// attempt would only wait behind that one, and behind a blocked port it
/// waits until the connection fails, seconds later: the delay would be spent
/// on a query that was never sent.
fn head_start(tier: &Tier) -> Duration {
    if tier.is_opening() {
        Duration::ZERO
    } else {
        DOH_HEDGE_DELAY
    }
}
