//! Blocks names whose registered domain is younger than a chosen age.
//!
//! The registration date comes from the registry's official record (RDAP, or
//! WHOIS where IANA lists no RDAP service; see `antiwire-lookup`). Dates are
//! cached for the process, not per resolver, so changing the age or restarting
//! the resolver does not repeat lookups.
//!
//! A name whose date is not cached yet waits a bounded time for its lookup on
//! the miss path. If the lookup does not finish in time the query fails open,
//! and the lookup keeps running so the next query for the name is decided from
//! the cache. A failed lookup, a registry with no record, or a TLD with no
//! lookup service also fails open: an unknown age is not a reason to block.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use moka::sync::Cache;
use moka::Expiry;
use parking_lot::Mutex;
use time::OffsetDateTime;
use tokio::sync::{watch, Semaphore};
use tracing::debug;

use antiwire_tuning::DNS_GATE_UPSTREAM_RESERVE;

use crate::dns_name::is_at_or_below;

/// Name the client shows for a block made by this guard.
pub(crate) const NEW_DOMAIN_BLOCK_LABEL: &str = "Newly Registered Domain";

/// Ages the settings accept, in days: one week, two weeks, one month, three months.
pub const NEW_DOMAIN_MAX_AGE_DAYS: [u32; 4] = [7, 14, 30, 90];

/// Default age for the setting.
pub(crate) const DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS: u32 = 30;

/// Whether `days` is one of [`NEW_DOMAIN_MAX_AGE_DAYS`].
#[must_use]
pub fn is_supported_new_domain_max_age(days: u32) -> bool {
    NEW_DOMAIN_MAX_AGE_DAYS.contains(&days)
}

/// Longest queries wait for one lookup, counted from when it started: a query
/// joining a lookup that has run this long fails open at once instead of
/// waiting again.
const FOREGROUND_BUDGET: Duration = Duration::from_millis(1_000);
/// How long a registration date is trusted. A domain only gets older, so this
/// only bounds how long a deleted and re-registered name keeps its old date.
const KNOWN_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a failed lookup is remembered before the name is looked up again.
const FAILED_TTL: Duration = Duration::from_secs(10 * 60);
/// Registered domains whose dates are kept.
const CACHE_CAPACITY: u64 = 50_000;
/// Lookups running at once; registries rate-limit bursts. A cold page load
/// can name dozens of registered domains, and every lookup queued past the
/// wait budget fails open, so the limit must cover a burst of that size.
pub(crate) const MAX_CONCURRENT_LOOKUPS: usize = 32;
/// Longest one lookup may hold a permit. The HTTP client allows a single
/// request 20 seconds; a registry that slow would keep a permit from the
/// names queued behind it.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Lookups started or queued before new names fail open without one.
const MAX_IN_FLIGHT: usize = 256;

/// What a registry said about one registered domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistrationAnswer {
    /// The registry published a creation date.
    Registered(OffsetDateTime),
    /// The registry answered without a creation date, has no record, or the
    /// TLD has no lookup service.
    Unknown,
    /// The lookup could not be completed; retried after [`FAILED_TTL`].
    Failed,
}

type LookupFuture<'a> = Pin<Box<dyn Future<Output = RegistrationAnswer> + Send + 'a>>;

/// Where registration dates come from. Tests supply their own.
pub(crate) trait RegistrationSource: Send + Sync + 'static {
    fn lookup<'a>(&'a self, domain: &'a str) -> LookupFuture<'a>;
}

/// The official registry record, through `antiwire-lookup`.
struct RegistryLookup(Arc<antiwire_lookup::Lookup>);

impl RegistrationSource for RegistryLookup {
    fn lookup<'a>(&'a self, domain: &'a str) -> LookupFuture<'a> {
        Box::pin(async move {
            match self.0.lookup_registry(domain).await {
                Ok(record) => record
                    .registered_at
                    .map_or(RegistrationAnswer::Unknown, RegistrationAnswer::Registered),
                Err(
                    antiwire_lookup::Error::NotFound(_)
                    | antiwire_lookup::Error::NoAuthority(_)
                    | antiwire_lookup::Error::InvalidDomain
                    | antiwire_lookup::Error::Malformed,
                ) => RegistrationAnswer::Unknown,
                Err(error) => {
                    debug!(domain, %error, "registration lookup failed");
                    RegistrationAnswer::Failed
                }
            }
        })
    }
}

/// Keeps a date or a definite "unknown" for [`KNOWN_TTL`], and a failed
/// lookup for [`FAILED_TTL`], each counted from when it was stored.
struct AnswerLifetime;

impl AnswerLifetime {
    fn of(answer: RegistrationAnswer) -> Duration {
        if answer == RegistrationAnswer::Failed {
            FAILED_TTL
        } else {
            KNOWN_TTL
        }
    }
}

impl Expiry<Box<str>, RegistrationAnswer> for AnswerLifetime {
    fn expire_after_create(
        &self,
        _domain: &Box<str>,
        answer: &RegistrationAnswer,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(Self::of(*answer))
    }

    /// A new answer replaces the old one's lifetime too: a date that follows a
    /// failed lookup is kept for the full day.
    fn expire_after_update(
        &self,
        _domain: &Box<str>,
        answer: &RegistrationAnswer,
        _updated_at: Instant,
        _remaining: Option<Duration>,
    ) -> Option<Duration> {
        Some(Self::of(*answer))
    }
}

/// A running lookup and when it was started.
#[derive(Clone)]
struct Pending {
    answer: watch::Receiver<Option<RegistrationAnswer>>,
    started: tokio::time::Instant,
}

/// Registration dates by registered domain, with the lookups still running.
pub(crate) struct RegistrationCache {
    source: Arc<dyn RegistrationSource>,
    known: Cache<Box<str>, RegistrationAnswer>,
    in_flight: Mutex<HashMap<Box<str>, Pending>>,
    permits: Arc<Semaphore>,
}

impl RegistrationCache {
    pub(crate) fn new(source: Arc<dyn RegistrationSource>) -> Arc<Self> {
        Arc::new(Self {
            source,
            known: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .expire_after(AnswerLifetime)
                .build(),
            in_flight: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
        })
    }

    fn cached(&self, domain: &str) -> Option<RegistrationAnswer> {
        self.known.get(domain)
    }

    /// Joins the running lookup for `domain` or starts one. `None` when too
    /// many are already running.
    fn start_or_join(self: &Arc<Self>, domain: &str) -> Option<Pending> {
        let mut in_flight = self.in_flight.lock();
        if let Some(pending) = in_flight.get(domain) {
            return Some(pending.clone());
        }
        if in_flight.len() >= MAX_IN_FLIGHT {
            return None;
        }
        let (sender, receiver) = watch::channel(None);
        let pending = Pending {
            answer: receiver,
            started: tokio::time::Instant::now(),
        };
        in_flight.insert(domain.into(), pending.clone());
        drop(in_flight);

        let cache = Arc::clone(self);
        let domain: Box<str> = domain.into();
        tokio::spawn(async move {
            let entry = InFlightEntry {
                cache: Arc::clone(&cache),
                domain: domain.clone(),
            };
            let answer = match Arc::clone(&cache.permits).acquire_owned().await {
                Ok(_permit) => tokio::time::timeout(LOOKUP_TIMEOUT, cache.source.lookup(&domain))
                    .await
                    .unwrap_or(RegistrationAnswer::Failed),
                Err(_) => RegistrationAnswer::Failed,
            };
            // Cached before the entry goes, so no query starts another lookup.
            cache.known.insert(domain, answer);
            drop(entry);
            // Nobody may be waiting any more; the cache already has the answer.
            let _ = sender.send(Some(answer));
        });
        Some(pending)
    }

    /// The answer for `domain`, waiting at most `budget` and never past
    /// [`FOREGROUND_BUDGET`] after the lookup started.
    async fn answer_within(
        self: &Arc<Self>,
        domain: &str,
        budget: Duration,
    ) -> Option<RegistrationAnswer> {
        if let Some(answer) = self.cached(domain) {
            return Some(answer);
        }
        let Pending {
            answer: mut pending,
            started,
        } = self.start_or_join(domain)?;
        let budget = budget.min(FOREGROUND_BUDGET.saturating_sub(started.elapsed()));
        if budget.is_zero() {
            return None;
        }
        let answer = tokio::time::timeout(budget, pending.wait_for(Option::is_some))
            .await
            .ok()?
            .ok()?;
        *answer
    }

    #[cfg(test)]
    pub(crate) fn insert_for_test(&self, domain: &str, answer: RegistrationAnswer) {
        self.known.insert(domain.into(), answer);
    }
}

/// Registration dates from the official registries, shared by every
/// resolver the daemon builds, so a settings change or a resolver restart
/// does not repeat lookups.
#[derive(Clone)]
pub struct RegistrationDates(pub(crate) Arc<RegistrationCache>);

impl RegistrationDates {
    /// Dates read through `lookup`, which also serves the record inspector,
    /// so both share its cached IANA bootstrap.
    #[must_use]
    pub fn official(lookup: Arc<antiwire_lookup::Lookup>) -> Self {
        Self(RegistrationCache::new(Arc::new(RegistryLookup(lookup))))
    }
}

/// A running lookup's place in [`RegistrationCache::in_flight`], released
/// however the lookup ends.
///
/// A lookup that panics must still free its slot: left behind, the entry would
/// count against [`MAX_IN_FLIGHT`] forever, and every later query for the domain
/// would join a lookup that never answers, so its date would never be learned.
/// Waiters see the dropped sender and fail open.
struct InFlightEntry {
    cache: Arc<RegistrationCache>,
    domain: Box<str>,
}

impl Drop for InFlightEntry {
    fn drop(&mut self) {
        self.cache.in_flight.lock().remove(&self.domain);
    }
}

/// What the guard decided for one query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NewDomainVerdict {
    Block,
    Allow,
    /// Not cached; the miss path must wait for a lookup.
    Pending,
}

/// Blocks names whose registered domain is younger than `max_age`.
pub(crate) struct NewDomainGuard {
    max_age: time::Duration,
    registrations: Arc<RegistrationCache>,
}

impl NewDomainGuard {
    pub(crate) fn new(max_age_days: u32, registrations: Arc<RegistrationCache>) -> Self {
        Self {
            max_age: time::Duration::days(i64::from(max_age_days)),
            registrations,
        }
    }

    /// Decides from the cache alone, for the synchronous path.
    pub(crate) fn check_cached(&self, name: &str) -> NewDomainVerdict {
        let Some(domain) = registered_domain(name) else {
            return NewDomainVerdict::Allow;
        };
        match self.registrations.cached(domain) {
            Some(answer) => self.verdict(answer),
            None if waits_for_lookup(name) => NewDomainVerdict::Pending,
            None => {
                // Answered without waiting, but looked up for the next query.
                let _ = self.registrations.start_or_join(domain);
                NewDomainVerdict::Allow
            }
        }
    }

    /// Decides for the miss path, waiting for a lookup within the query's
    /// remaining time less [`DNS_GATE_UPSTREAM_RESERVE`], which is left for
    /// the DNS request itself. Never returns [`NewDomainVerdict::Pending`].
    pub(crate) async fn check(&self, name: &str, remaining: Duration) -> NewDomainVerdict {
        let Some(domain) = registered_domain(name) else {
            return NewDomainVerdict::Allow;
        };
        let budget = if waits_for_lookup(name) {
            FOREGROUND_BUDGET.min(remaining.saturating_sub(DNS_GATE_UPSTREAM_RESERVE))
        } else {
            Duration::ZERO
        };
        match self.registrations.answer_within(domain, budget).await {
            Some(answer) => self.verdict(answer),
            None => NewDomainVerdict::Allow,
        }
    }

    fn verdict(&self, answer: RegistrationAnswer) -> NewDomainVerdict {
        match answer {
            RegistrationAnswer::Registered(at) if is_younger_than(at, self.max_age) => {
                NewDomainVerdict::Block
            }
            _ => NewDomainVerdict::Allow,
        }
    }
}

/// A date in the future counts as new: it is the registry's clock or ours that
/// is off, and the domain cannot be older than the date says.
fn is_younger_than(registered_at: OffsetDateTime, max_age: time::Duration) -> bool {
    OffsetDateTime::now_utc() - registered_at < max_age
}

/// The registered domain for a normalized name (lowercase, no trailing dot),
/// or `None` when the name is not under a public suffix and so has no
/// registry to ask.
fn registered_domain(name: &str) -> Option<&str> {
    if is_at_or_below(name, "arpa") || is_at_or_below(name, "iana.org") {
        // Reverse lookups have no registration. IANA serves the RDAP
        // bootstrap every lookup starts from, so its own name must never wait
        // on one.
        return None;
    }
    let domain = psl::domain(name.as_bytes())?;
    if !domain.suffix().is_known() {
        return None;
    }
    std::str::from_utf8(domain.as_bytes()).ok()
}

/// Whether a query should wait for its lookup.
///
/// Registry and registrar lookup servers are conventionally named `rdap.` or
/// `whois.`. The lookup that is resolving such a name may be the one this
/// query would wait for, so these names are answered at once and looked up in
/// the background. Other lookup servers are bounded by the wait budget.
fn waits_for_lookup(name: &str) -> bool {
    !(name.starts_with("rdap.") || name.starts_with("whois."))
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Answers from a fixed table after `delay`, counting calls.
    pub(crate) struct FixedSource {
        pub(crate) answers: HashMap<&'static str, RegistrationAnswer>,
        pub(crate) delay: Duration,
        pub(crate) calls: AtomicUsize,
    }

    impl FixedSource {
        pub(crate) fn new(
            answers: impl IntoIterator<Item = (&'static str, RegistrationAnswer)>,
            delay: Duration,
        ) -> Arc<Self> {
            Arc::new(Self {
                answers: answers.into_iter().collect(),
                delay,
                calls: AtomicUsize::new(0),
            })
        }

        pub(crate) fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl RegistrationSource for FixedSource {
        fn lookup<'a>(&'a self, domain: &'a str) -> LookupFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::time::sleep(self.delay).await;
                self.answers
                    .get(domain)
                    .copied()
                    .unwrap_or(RegistrationAnswer::Unknown)
            })
        }
    }

    pub(crate) fn days_ago(days: i64) -> RegistrationAnswer {
        RegistrationAnswer::Registered(OffsetDateTime::now_utc() - time::Duration::days(days))
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{days_ago, FixedSource};
    use super::*;

    fn guard(days: u32, source: Arc<FixedSource>) -> NewDomainGuard {
        NewDomainGuard::new(days, RegistrationCache::new(source))
    }

    #[test]
    fn a_failed_lookup_is_kept_briefly_and_a_later_date_for_a_day() {
        let domain: Box<str> = "example.com".into();
        let now = Instant::now();
        assert_eq!(
            AnswerLifetime.expire_after_create(&domain, &RegistrationAnswer::Failed, now),
            Some(FAILED_TTL)
        );
        assert_eq!(
            AnswerLifetime.expire_after_update(
                &domain,
                &days_ago(400),
                now,
                Some(Duration::from_secs(1)),
            ),
            Some(KNOWN_TTL)
        );
    }

    #[test]
    fn supported_ages_are_one_week_two_weeks_one_month_and_three_months() {
        for days in [7, 14, 30, 90] {
            assert!(is_supported_new_domain_max_age(days));
        }
        for days in [0, 1, 31, 365] {
            assert!(!is_supported_new_domain_max_age(days));
        }
        assert!(is_supported_new_domain_max_age(
            DEFAULT_NEW_DOMAIN_MAX_AGE_DAYS
        ));
    }

    #[test]
    fn subdomains_are_judged_by_their_registered_domain() {
        assert_eq!(registered_domain("www.example.com"), Some("example.com"));
        assert_eq!(
            registered_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registered_domain("example.com"), Some("example.com"));
    }

    #[test]
    fn names_without_a_registry_are_never_looked_up() {
        assert_eq!(registered_domain("printer.lan"), None);
        assert_eq!(registered_domain("com"), None);
        assert_eq!(registered_domain("1.2.0.192.in-addr.arpa"), None);
        assert_eq!(registered_domain("data.iana.org"), None);
    }

    #[test]
    fn lookup_servers_do_not_wait_for_a_lookup() {
        assert!(!waits_for_lookup("rdap.verisign.com"));
        assert!(!waits_for_lookup("whois.nic.xyz"));
        assert!(waits_for_lookup("www.example.com"));
    }

    #[tokio::test]
    async fn blocks_a_domain_younger_than_the_age_and_allows_an_older_one() {
        let source = FixedSource::new(
            [
                ("fresh.com", days_ago(3)),
                ("month.com", days_ago(20)),
                ("old.com", days_ago(4_000)),
            ],
            Duration::ZERO,
        );
        let week = guard(7, Arc::clone(&source));
        let quarter = guard(90, source);
        let wait = Duration::from_secs(2);

        assert_eq!(
            week.check("www.fresh.com", wait).await,
            NewDomainVerdict::Block
        );
        assert_eq!(week.check("month.com", wait).await, NewDomainVerdict::Allow);
        assert_eq!(
            quarter.check("month.com", wait).await,
            NewDomainVerdict::Block
        );
        assert_eq!(
            quarter.check("old.com", wait).await,
            NewDomainVerdict::Allow
        );
    }

    #[tokio::test]
    async fn unknown_or_failed_ages_fail_open() {
        let source = FixedSource::new(
            [
                ("unknown.com", RegistrationAnswer::Unknown),
                ("failed.com", RegistrationAnswer::Failed),
            ],
            Duration::ZERO,
        );
        let guard = guard(90, source);
        let wait = Duration::from_secs(2);
        assert_eq!(
            guard.check("unknown.com", wait).await,
            NewDomainVerdict::Allow
        );
        assert_eq!(
            guard.check("failed.com", wait).await,
            NewDomainVerdict::Allow
        );
    }

    #[tokio::test]
    async fn a_future_registration_date_counts_as_new() {
        let source = FixedSource::new([("future.com", days_ago(-2))], Duration::ZERO);
        let guard = guard(7, source);
        assert_eq!(
            guard.check("future.com", Duration::from_secs(2)).await,
            NewDomainVerdict::Block
        );
    }

    #[tokio::test]
    async fn the_sync_path_defers_until_the_date_is_cached() {
        let source = FixedSource::new([("fresh.com", days_ago(1))], Duration::ZERO);
        let guard = guard(7, Arc::clone(&source));
        assert_eq!(guard.check_cached("fresh.com"), NewDomainVerdict::Pending);
        assert_eq!(
            guard.check("fresh.com", Duration::from_secs(2)).await,
            NewDomainVerdict::Block
        );
        assert_eq!(guard.check_cached("a.fresh.com"), NewDomainVerdict::Block);
        assert_eq!(
            source.calls(),
            1,
            "the date is cached per registered domain"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_lookup_fails_open_and_decides_the_next_query() {
        let source = FixedSource::new([("slow.com", days_ago(1))], Duration::from_secs(5));
        let guard = guard(7, Arc::clone(&source));
        assert_eq!(
            guard.check("slow.com", Duration::from_secs(2)).await,
            NewDomainVerdict::Allow,
            "the wait is bounded"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        assert_eq!(guard.check_cached("slow.com"), NewDomainVerdict::Block);
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_queries_share_one_lookup() {
        let source = FixedSource::new([("shared.com", days_ago(1))], Duration::from_millis(200));
        let guard = Arc::new(guard(7, Arc::clone(&source)));
        let checks = (0..5).map(|_| {
            let guard = Arc::clone(&guard);
            tokio::spawn(async move { guard.check("shared.com", Duration::from_secs(2)).await })
        });
        for check in checks {
            assert_eq!(check.await.unwrap(), NewDomainVerdict::Block);
        }
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test]
    #[ignore = "queries IANA and the .com registry"]
    async fn the_registry_dates_a_long_registered_domain() {
        let lookup = antiwire_lookup::Lookup::new().expect("lookup client");
        let dates = RegistrationCache::new(Arc::new(RegistryLookup(Arc::new(lookup))));
        let guard = NewDomainGuard::new(90, Arc::clone(&dates));
        assert_eq!(
            guard.check("www.example.com", Duration::from_secs(2)).await,
            NewDomainVerdict::Allow
        );
        let answer = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if let Some(answer) = dates.cached("example.com") {
                    return answer;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the lookup finishes");
        let RegistrationAnswer::Registered(at) = answer else {
            panic!("expected a registration date, got {answer:?}");
        };
        assert_eq!(at.date().to_string(), "1995-08-14");
    }

    #[tokio::test(start_paused = true)]
    async fn a_query_joining_an_overdue_lookup_does_not_wait_again() {
        let source = FixedSource::new([("stuck.com", days_ago(1))], Duration::from_secs(4));
        let guard = guard(7, Arc::clone(&source));
        let wait = Duration::from_secs(2);
        assert_eq!(
            guard.check("stuck.com", wait).await,
            NewDomainVerdict::Allow
        );

        let started = tokio::time::Instant::now();
        assert_eq!(
            guard.check("stuck.com", wait).await,
            NewDomainVerdict::Allow
        );
        assert_eq!(
            started.elapsed(),
            Duration::ZERO,
            "the lookup already had its budget"
        );
        assert_eq!(source.calls(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_joining_query_waits_only_for_what_is_left_of_the_budget() {
        let source = FixedSource::new([("slow.com", days_ago(1))], Duration::from_secs(4));
        let guard = Arc::new(guard(7, source));
        assert_eq!(guard.check_cached("rdap.slow.com"), NewDomainVerdict::Allow);
        tokio::time::sleep(Duration::from_millis(600)).await;

        let started = tokio::time::Instant::now();
        let _ = guard.check("slow.com", Duration::from_secs(2)).await;
        assert_eq!(
            started.elapsed(),
            FOREGROUND_BUDGET.saturating_sub(Duration::from_millis(600))
        );
    }

    struct PanickingSource;

    impl RegistrationSource for PanickingSource {
        fn lookup<'a>(&'a self, _domain: &'a str) -> LookupFuture<'a> {
            Box::pin(async { panic!("registry parser bug") })
        }
    }

    #[tokio::test]
    async fn a_panicking_lookup_frees_its_in_flight_slot() {
        let dates = RegistrationCache::new(Arc::new(PanickingSource));
        let answer = dates
            .answer_within("panic.com", Duration::from_secs(1))
            .await;
        assert_eq!(answer, None, "waiters fail open");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !dates.in_flight.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the entry is released, so a later query looks the domain up again");
    }

    #[tokio::test(start_paused = true)]
    async fn a_stuck_lookup_gives_up_and_frees_its_permit() {
        let source = FixedSource::new([], Duration::from_secs(60));
        let dates = RegistrationCache::new(source);
        let _ = dates.start_or_join("stuck.com");
        tokio::time::sleep(LOOKUP_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(dates.cached("stuck.com"), Some(RegistrationAnswer::Failed));
        assert_eq!(dates.permits.available_permits(), MAX_CONCURRENT_LOOKUPS);
    }

    #[tokio::test]
    async fn lookup_servers_are_answered_at_once_and_looked_up_behind() {
        let source = FixedSource::new([("fresh.com", days_ago(1))], Duration::ZERO);
        let guard = guard(7, Arc::clone(&source));
        assert_eq!(
            guard.check_cached("rdap.fresh.com"),
            NewDomainVerdict::Allow
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            while guard.check_cached("rdap.fresh.com") != NewDomainVerdict::Block {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the background lookup decides later queries");
    }
}
