//! Upstream concurrency gates for foreground and background DNS work.
//!
//! The limits belong to one [`UpstreamAdmission`], which is per network
//! generation: a network reset builds a new one with fresh semaphores, so the
//! limits are not process-wide.

use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_resolver::net::NetError;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use antiwire_tuning::{
    DNS_MAX_CONCURRENT_BACKGROUND_UPSTREAM, DNS_MAX_CONCURRENT_UPSTREAM, DNS_TRANSPORT_TIMEOUT,
    DNS_UPSTREAM_ADMISSION_TIMEOUT,
};

use super::resolver::{resolve_error_msg, UpstreamAnswer, UpstreamDns};

/// Whether upstream work is client-visible or speculative refresh/prefetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionClass {
    Foreground,
    Background,
}

/// Holds upstream admission permits until dropped.
pub(crate) struct AdmissionPermits {
    _foreground: OwnedSemaphorePermit,
    _background: Option<OwnedSemaphorePermit>,
}

/// Upstream resolver wrapped with bounded foreground/background admission.
///
/// Built once per network generation by `QueryEngine::try_new` and
/// `reset_after_network_change`; the semaphores here are not shared across them.
pub(crate) struct UpstreamAdmission {
    inner: Arc<UpstreamDns>,
    foreground: Arc<Semaphore>,
    background: Arc<Semaphore>,
}

impl UpstreamAdmission {
    #[must_use]
    pub(crate) fn new(inner: Arc<UpstreamDns>) -> Self {
        Self {
            inner,
            foreground: Arc::new(Semaphore::new(DNS_MAX_CONCURRENT_UPSTREAM as usize)),
            background: Arc::new(Semaphore::new(
                DNS_MAX_CONCURRENT_BACKGROUND_UPSTREAM as usize,
            )),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn inner(&self) -> &Arc<UpstreamDns> {
        &self.inner
    }

    /// True when every upstream tier is down.
    #[must_use]
    pub(crate) fn degraded(&self) -> bool {
        self.inner.endpoints_degraded()
    }

    /// True when a foreground exchange started now would fail at once.
    #[must_use]
    pub(crate) fn fails_fast(&self) -> bool {
        self.inner.fails_fast()
    }

    /// Acquires admission for the requested class.
    pub(crate) async fn acquire(
        &self,
        class: AdmissionClass,
        remaining_budget: Option<std::time::Duration>,
    ) -> Option<AdmissionPermits> {
        match class {
            AdmissionClass::Foreground => {
                let wait_timeout = match remaining_budget {
                    Some(budget) => {
                        // Reserve a full transport attempt. Waiting for a permit
                        // past `budget - DNS_TRANSPORT_TIMEOUT` cannot leave the
                        // exchange enough time, so a query with nothing left
                        // after the reservation is denied now rather than
                        // guaranteed to time out downstream. There is no
                        // admission floor: a sub-floor budget must not outlive
                        // its own deadline.
                        let reserved = budget.saturating_sub(DNS_TRANSPORT_TIMEOUT);
                        if reserved.is_zero() {
                            return None;
                        }
                        reserved.min(std::time::Duration::from_secs(1))
                    }
                    None => DNS_UPSTREAM_ADMISSION_TIMEOUT,
                };
                let foreground = timeout(wait_timeout, self.foreground.clone().acquire_owned())
                    .await
                    .ok()?
                    .ok()?;
                Some(AdmissionPermits {
                    _foreground: foreground,
                    _background: None,
                })
            }
            AdmissionClass::Background => {
                let background = self.background.clone().try_acquire_owned().ok()?;
                let foreground = self.foreground.clone().try_acquire_owned().ok()?;
                Some(AdmissionPermits {
                    _foreground: foreground,
                    _background: Some(background),
                })
            }
        }
    }

    /// Forwards `request` using an already-held admission permit.
    ///
    /// Takes the permits by value and hands them to the exchange's attempts,
    /// so they are released only when the last attempt finishes. An attempt
    /// that loses the race or outlives the deadline is still upstream work,
    /// and the limits must count it.
    pub(crate) async fn exchange_admitted(
        &self,
        request: &Message,
        permits: AdmissionPermits,
    ) -> Result<UpstreamAnswer, NetError> {
        self.inner
            .exchange_guarded(request, None, Some(Arc::new(permits)))
            .await
    }

    /// Forwards `request` after acquiring the appropriate admission gate.
    pub(crate) async fn exchange(
        &self,
        request: &Message,
        class: AdmissionClass,
        remaining_budget: Option<std::time::Duration>,
    ) -> Result<UpstreamAnswer, NetError> {
        let acquire_started = std::time::Instant::now();
        let permits = self
            .acquire(class, remaining_budget)
            .await
            .ok_or_else(|| resolve_error_msg(super::ADMISSION_DENIED))?;
        let leftover =
            remaining_budget.map(|budget| budget.saturating_sub(acquire_started.elapsed()));
        self.inner
            .exchange_guarded(request, leftover, Some(Arc::new(permits)))
            .await
    }
}

pub(crate) type SharedUpstreamAdmission = Arc<UpstreamAdmission>;

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::upstream::build_upstream_dns;

    #[test]
    fn semaphore_capacities_match_tuning() {
        assert_eq!(DNS_MAX_CONCURRENT_UPSTREAM, 256);
        assert_eq!(DNS_MAX_CONCURRENT_BACKGROUND_UPSTREAM, 16);
    }

    #[tokio::test]
    async fn foreground_admission_times_out_when_saturated() {
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &["127.0.0.1:1".to_owned()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);
        let mut permits = Vec::new();
        for _ in 0..DNS_MAX_CONCURRENT_UPSTREAM as usize {
            permits.push(
                admission
                    .acquire(AdmissionClass::Foreground, None)
                    .await
                    .expect("permit"),
            );
        }
        let late = admission.acquire(AdmissionClass::Foreground, None).await;
        assert!(late.is_none());
    }

    /// An attempt that outlives its exchange still holds the exchange's
    /// permit, so the limit counts upstream work rather than callers.
    #[tokio::test]
    async fn a_timed_out_exchange_keeps_its_permit_until_the_attempt_ends() {
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &[silent.local_addr().expect("addr").to_string()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);
        let capacity = DNS_MAX_CONCURRENT_UPSTREAM as usize;
        let mut request = Message::new(
            7,
            hickory_proto::op::MessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        request.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii("held.example.").expect("name"),
            hickory_proto::rr::RecordType::A,
        ));

        let budget = DNS_TRANSPORT_TIMEOUT + Duration::from_millis(100);
        let result = admission
            .exchange(&request, AdmissionClass::Foreground, Some(budget))
            .await;
        assert!(result.is_err(), "a silent upstream never answers");
        assert_eq!(
            admission.foreground.available_permits(),
            capacity - 1,
            "the attempt is still waiting on the silent upstream"
        );

        let released = tokio::time::timeout(Duration::from_secs(5), async {
            while admission.foreground.available_permits() < capacity {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(released.is_ok(), "the permit returns once the attempt ends");
    }

    #[tokio::test]
    async fn background_acquire_fails_when_foreground_pool_is_full() {
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &["127.0.0.1:1".to_owned()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);
        let mut permits = Vec::new();
        for _ in 0..DNS_MAX_CONCURRENT_UPSTREAM as usize {
            permits.push(
                admission
                    .acquire(AdmissionClass::Foreground, None)
                    .await
                    .expect("permit"),
            );
        }

        let background = admission.acquire(AdmissionClass::Background, None).await;
        assert!(background.is_none());
    }

    #[tokio::test]
    async fn foreground_admission_times_out_within_budget() {
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &["127.0.0.1:1".to_owned()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);
        let mut permits = Vec::new();
        for _ in 0..DNS_MAX_CONCURRENT_UPSTREAM as usize {
            permits.push(
                admission
                    .acquire(AdmissionClass::Foreground, None)
                    .await
                    .expect("permit"),
            );
        }

        let start = std::time::Instant::now();
        let late = admission.acquire(AdmissionClass::Foreground, None).await;
        let elapsed = start.elapsed();
        assert!(late.is_none());
        assert!(elapsed < Duration::from_millis(500));
        assert!(elapsed >= antiwire_tuning::DNS_UPSTREAM_ADMISSION_TIMEOUT / 2);
    }

    #[tokio::test]
    async fn foreground_admission_denies_when_budget_cannot_cover_transport() {
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &["127.0.0.1:1".to_owned()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);

        let start = std::time::Instant::now();
        let denied = admission
            .acquire(AdmissionClass::Foreground, Some(DNS_TRANSPORT_TIMEOUT / 2))
            .await;
        assert!(denied.is_none());
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "a budget below the transport cost must be denied immediately"
        );
    }

    #[tokio::test]
    async fn foreground_admission_waits_within_reserved_budget() {
        let upstream = Arc::new(
            build_upstream_dns(
                crate::settings::DnsProtocol::Udp,
                &["127.0.0.1:1".to_owned()],
            )
            .expect("upstream"),
        );
        let admission = UpstreamAdmission::new(upstream);

        let permit = admission
            .acquire(
                AdmissionClass::Foreground,
                Some(DNS_TRANSPORT_TIMEOUT + Duration::from_millis(125)),
            )
            .await;
        assert!(
            permit.is_some(),
            "a budget with room after the transport reservation is admitted"
        );
    }
}
