use crate::dns_parse::canonicalize_ip;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

type DnsKey = (u32, IpAddr);
type Expiration = (u64, u64, DnsKey);
const MAX_DOMAINS_PER_KEY: usize = 10;

/// Resolved domain associated with a PID and remote address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsHint {
    /// Lowercase domain without a trailing dot.
    pub domain: String,
    /// Expiry timestamp, in Unix epoch milliseconds.
    pub expires_at: u64,
}

/// Evidence scope for a resolved DNS hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsHintProvenance {
    /// The hint was recorded for the same process.
    Process,
    /// The hint came from the PID-zero shared namespace.
    Shared,
}

/// A live DNS hint together with its attribution provenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolvedDnsHint<'a> {
    /// Lowercase domain without a trailing dot.
    pub domain: &'a str,
    /// Scope from which the hint was resolved.
    pub provenance: DnsHintProvenance,
}

/// What a hint map says an address was for one process around a point in time.
///
/// Returned by [`DnsHintMap::name_at`], which unlike the `resolve` methods
/// also uses hints kept past their expiry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsHintAt<'a> {
    /// The one name valid in the window asked about.
    Live(&'a str),
    /// No name was valid in the window, and this is the only one kept.
    Retained(&'a str),
    /// Several names were valid in the window.
    Ambiguous,
    /// No name is kept, or several are and none was valid in the window.
    None,
}

/// When one of several competing names is likely enough the one a connection
/// went to: it was asked for just before the connection opened, and clearly
/// after the others. See [`DnsHintMap::nearest_at`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NearestHint {
    /// The name must have been recorded no longer than this before the window
    /// starts, in milliseconds.
    pub within_ms: u64,
    /// And at least this much later than every other name valid in the
    /// window, in milliseconds.
    pub lead_ms: u64,
}

/// Capacity-bounded, TTL-aware DNS attribution cache.
///
/// Retains up to ten distinct domains per `(pid, address)`, each with its own
/// expiry. A repeated name refreshes that candidate; an eleventh distinct name
/// evicts the least recently recorded candidate.
///
/// A map made by [`Self::with_retention`] keeps each candidate for a while
/// after it expires. The `resolve` methods never return an expired candidate;
/// [`Self::name_at`] does, when nothing better is known.
#[derive(Debug)]
pub struct DnsHintMap {
    entries: HashMap<DnsKey, DnsCandidates>,
    expirations: BTreeSet<Expiration>,
    generation: u64,
    max_entries: usize,
    /// How long a candidate is kept after it expires, in milliseconds.
    retention_ms: u64,
}

#[derive(Debug)]
struct DnsEntry {
    hint: DnsHint,
    generation: u64,
    /// When the answer was recorded, in Unix epoch milliseconds.
    recorded_at: u64,
}

/// Names discarded by the per-key cap, summarized so the retained set is not
/// mistaken for unique while they would still be valid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OmittedEvidence {
    /// Longest validity among the discarded names; indexed in `expirations`.
    expires_at: u64,
    /// Generation of the name `expires_at` came from.
    generation: u64,
    /// When the most recently recorded discarded name was recorded, so a PID
    /// generation cutoff can tell whether any of them belong to the new process.
    newest_recorded_at: u64,
}

#[derive(Debug, Default)]
struct DnsCandidates {
    entries: Vec<DnsEntry>,
    omitted: Option<OmittedEvidence>,
}

impl DnsCandidates {
    fn has_live_evidence(&self, now: u64) -> bool {
        self.omitted
            .is_some_and(|omitted| now <= omitted.expires_at)
            || self
                .entries
                .iter()
                .any(|entry| now <= entry.hint.expires_at)
    }
}

impl DnsHintMap {
    /// Clears all cached process and shared DNS hints.
    #[doc(hidden)]
    pub fn clear(&mut self) {
        self.entries.clear();
        self.expirations.clear();
    }
    /// Creates a DNS hint cache limited to `max_entries` PID/address pairs.
    ///
    /// # Panics
    ///
    /// Panics when `max_entries` is zero.
    pub fn new(max_entries: usize) -> Self {
        Self::with_retention(max_entries, 0)
    }

    /// Creates a DNS hint cache limited to `max_entries` PID/address pairs
    /// that keeps each hint for `retention_ms` after it expires.
    ///
    /// A process goes on using an address after the answer that gave it has
    /// expired, from its own cache, so an expired hint is still evidence of
    /// what the address was to that process. Only [`Self::name_at`] reads it.
    ///
    /// # Panics
    ///
    /// Panics when `max_entries` is zero.
    pub fn with_retention(max_entries: usize, retention_ms: u64) -> Self {
        assert!(max_entries > 0, "DNS hint capacity must be non-zero");
        Self {
            entries: HashMap::with_capacity(max_entries.min(1024)),
            expirations: BTreeSet::new(),
            generation: 0,
            max_entries,
            retention_ms,
        }
    }

    /// Associates every answer with a normalized query until the TTL expires.
    pub fn insert<I>(&mut self, pid: u32, query: &str, answers: I, now: u64, ttl_ms: u64)
    where
        I: IntoIterator<Item = IpAddr>,
    {
        let domain = normalize_dns_name(query);
        if domain.is_empty() {
            return;
        }
        self.sweep(now);
        let expires_at = now.saturating_add(ttl_ms);
        for answer in answers.into_iter().map(canonicalize_ip) {
            let key = (pid, answer);
            if self.entries.len() >= self.max_entries && !self.entries.contains_key(&key) {
                self.evict_one();
            }
            self.generation = self.generation.wrapping_add(1);
            let generation = self.generation;
            let candidates = self.entries.entry(key).or_default();
            let duplicate = candidates
                .entries
                .iter()
                .position(|entry| entry.hint.domain == domain);
            if let Some(index) = duplicate {
                let replaced = candidates.entries.remove(index);
                self.expirations
                    .remove(&(replaced.hint.expires_at, replaced.generation, key));
            } else if candidates.entries.len() == MAX_DOMAINS_PER_KEY {
                let evicted = candidates.entries.remove(0);
                self.expirations
                    .remove(&(evicted.hint.expires_at, evicted.generation, key));
                let newest_recorded_at = candidates.omitted.map_or(evicted.recorded_at, |prior| {
                    prior.newest_recorded_at.max(evicted.recorded_at)
                });
                match &mut candidates.omitted {
                    Some(prior) if prior.expires_at >= evicted.hint.expires_at => {
                        prior.newest_recorded_at = newest_recorded_at;
                    }
                    slot => {
                        if let Some(prior) = slot.take() {
                            self.expirations
                                .remove(&(prior.expires_at, prior.generation, key));
                        }
                        *slot = Some(OmittedEvidence {
                            expires_at: evicted.hint.expires_at,
                            generation: evicted.generation,
                            newest_recorded_at,
                        });
                        self.expirations
                            .insert((evicted.hint.expires_at, evicted.generation, key));
                    }
                }
            }
            candidates.entries.push(DnsEntry {
                hint: DnsHint {
                    domain: domain.clone(),
                    expires_at,
                },
                generation,
                recorded_at: now,
            });
            self.expirations.insert((expires_at, generation, key));
        }
    }

    /// Resolves a unique live hint, preferring the exact PID and then PID zero.
    ///
    /// Returns `None` if multiple candidates remain in the preferred scope.
    pub fn resolve(&self, pid: u32, remote: IpAddr, now: u64) -> Option<&str> {
        self.resolve_with_provenance(pid, remote, now)
            .map(|resolved| resolved.domain)
    }

    /// Resolves a unique live hint and reports whether it is process-scoped or shared.
    ///
    /// An ambiguous process-scoped match does not fall back to shared hints.
    pub fn resolve_with_provenance(
        &self,
        pid: u32,
        remote: IpAddr,
        now: u64,
    ) -> Option<ResolvedDnsHint<'_>> {
        if self.is_ambiguous(pid, remote, now) {
            return None;
        }
        self.resolve_candidates(pid, remote, now).next()
    }

    /// Returns up to ten live candidates, most recently recorded first.
    ///
    /// Prefers process-scoped candidates. Shared candidates are used only when
    /// the process has no live evidence. All returned hints have the same scope.
    /// Check [`Self::is_ambiguous`] before selecting a name: capacity eviction
    /// can leave omitted live evidence even if fewer than two names are returned.
    pub fn resolve_candidates(
        &self,
        pid: u32,
        remote: IpAddr,
        now: u64,
    ) -> impl Iterator<Item = ResolvedDnsHint<'_>> {
        self.preferred_candidates(pid, remote, now)
            .into_iter()
            .flat_map(move |(candidates, provenance)| {
                candidates
                    .entries
                    .iter()
                    .rev()
                    .filter(move |entry| now <= entry.hint.expires_at)
                    .map(move |entry| ResolvedDnsHint {
                        domain: &entry.hint.domain,
                        provenance,
                    })
            })
    }

    /// Whether the preferred scope contains multiple possible domains.
    ///
    /// Includes evidence discarded by the ten-domain cap until its TTL expires.
    pub fn is_ambiguous(&self, pid: u32, remote: IpAddr, now: u64) -> bool {
        self.preferred_candidates(pid, remote, now)
            .is_some_and(|(candidates, _)| {
                candidates
                    .omitted
                    .is_some_and(|omitted| now <= omitted.expires_at)
                    || candidates
                        .entries
                        .iter()
                        .filter(|entry| now <= entry.hint.expires_at)
                        .take(2)
                        .count()
                        > 1
            })
    }

    fn preferred_candidates(
        &self,
        pid: u32,
        remote: IpAddr,
        now: u64,
    ) -> Option<(&DnsCandidates, DnsHintProvenance)> {
        let remote = canonicalize_ip(remote);
        if pid > 0
            && let Some(candidates) = self
                .entries
                .get(&(pid, remote))
                .filter(|candidates| candidates.has_live_evidence(now))
        {
            return Some((candidates, DnsHintProvenance::Process));
        }
        self.entries
            .get(&(0, remote))
            .filter(|candidates| candidates.has_live_evidence(now))
            .map(|candidates| (candidates, DnsHintProvenance::Shared))
    }

    /// The name `pid` had for `remote` in the window `from..=until`, in Unix
    /// epoch milliseconds, which is normally the moment a connection opened
    /// and a little after.
    ///
    /// Names valid at some point in the window decide: one is
    /// [`DnsHintAt::Live`] and several are [`DnsHintAt::Ambiguous`]. When none
    /// was, a single kept name, expired before the window or recorded after
    /// it, is [`DnsHintAt::Retained`]. Only `pid`'s own hints are read: there
    /// is no fallback to PID zero.
    ///
    /// Hints recorded before `since` are ignored, as are names the per-address
    /// cap discarded before then. Pass the process's start time so a hint an
    /// earlier process with the same PID left behind cannot answer, or zero
    /// when it is unknown.
    pub fn name_at(
        &self,
        pid: u32,
        remote: IpAddr,
        from: u64,
        until: u64,
        since: u64,
    ) -> DnsHintAt<'_> {
        let Some(candidates) = self.entries.get(&(pid, canonicalize_ip(remote))) else {
            return DnsHintAt::None;
        };
        let kept = |expires_at: u64| expires_at.saturating_add(self.retention_ms) >= from;
        let omitted = candidates
            .omitted
            .filter(|omitted| omitted.newest_recorded_at >= since && kept(omitted.expires_at));
        let omitted_live = omitted.is_some_and(|omitted| from <= omitted.expires_at);
        let mut known = candidates
            .entries
            .iter()
            .filter(|entry| entry.recorded_at >= since && kept(entry.hint.expires_at));
        let mut live = known
            .clone()
            .filter(|entry| entry.recorded_at <= until && from <= entry.hint.expires_at);
        match (live.next(), live.next()) {
            (Some(_), Some(_)) => DnsHintAt::Ambiguous,
            (Some(_), None) | (None, _) if omitted_live => DnsHintAt::Ambiguous,
            (Some(entry), None) => DnsHintAt::Live(&entry.hint.domain),
            // A discarded name would be a second one, whichever it was.
            (None, _) if omitted.is_some() => DnsHintAt::None,
            (None, _) => match (known.next(), known.next()) {
                (Some(entry), None) => DnsHintAt::Retained(&entry.hint.domain),
                _ => DnsHintAt::None,
            },
        }
    }

    /// Of the names `pid` had for `remote` that were valid in the window
    /// `from..=until`, the one recorded last, when `rule` accepts it.
    ///
    /// A process asks for a name and then connects, so of several names that
    /// share an address, the one asked for just before a connection opened is
    /// the likeliest one it went to. This is a guess, not evidence: use it to
    /// name what [`Self::name_at`] reports as [`DnsHintAt::Ambiguous`], and
    /// say that the name was inferred. `None` when no name leads by enough,
    /// or when a name the per-address cap discarded may be among them.
    ///
    /// `since` is as for [`Self::name_at`].
    pub fn nearest_at(
        &self,
        pid: u32,
        remote: IpAddr,
        from: u64,
        until: u64,
        since: u64,
        rule: NearestHint,
    ) -> Option<&str> {
        let candidates = self.entries.get(&(pid, canonicalize_ip(remote)))?;
        let kept = |expires_at: u64| expires_at.saturating_add(self.retention_ms) >= from;
        let discarded = candidates.omitted.is_some_and(|omitted| {
            omitted.newest_recorded_at >= since
                && kept(omitted.expires_at)
                && from <= omitted.expires_at
        });
        if discarded {
            return None;
        }
        let live = || {
            candidates.entries.iter().filter(|entry| {
                entry.recorded_at >= since
                    && entry.recorded_at <= until
                    && from <= entry.hint.expires_at
            })
        };
        let nearest = live().max_by_key(|entry| entry.recorded_at)?;
        let recent = nearest.recorded_at.saturating_add(rule.within_ms) >= from;
        let leads = live().all(|entry| {
            std::ptr::eq(entry, nearest)
                || entry.recorded_at.saturating_add(rule.lead_ms) <= nearest.recorded_at
        });
        (recent && leads).then_some(nearest.hint.domain.as_str())
    }

    /// Forgets the hints `pid` recorded before `started_at`, in Unix epoch
    /// milliseconds: they belong to an earlier process that had the same PID.
    ///
    /// Returns the number of PID/address pairs removed.
    pub fn forget_before(&mut self, pid: u32, started_at: u64) -> usize {
        if pid == 0 {
            return 0;
        }
        let keys: Vec<DnsKey> = self
            .entries
            .keys()
            .filter(|(owner, _)| *owner == pid)
            .copied()
            .collect();
        let mut removed = 0;
        for key in keys {
            let Some(candidates) = self.entries.get_mut(&key) else {
                continue;
            };
            let expirations = &mut self.expirations;
            candidates.entries.retain(|entry| {
                let keep = entry.recorded_at >= started_at;
                if !keep {
                    expirations.remove(&(entry.hint.expires_at, entry.generation, key));
                }
                keep
            });
            // Discarded names all recorded before the start belonged to the
            // earlier process too, and must not keep this one's names ambiguous.
            if (candidates.entries.is_empty()
                || candidates
                    .omitted
                    .is_some_and(|omitted| omitted.newest_recorded_at < started_at))
                && let Some(omitted) = candidates.omitted.take()
            {
                self.expirations
                    .remove(&(omitted.expires_at, omitted.generation, key));
            }
            if candidates.entries.is_empty() {
                self.entries.remove(&key);
                removed += 1;
            }
        }
        removed
    }

    /// Deletes candidates that expired longer ago than the map retains them,
    /// and returns the number of PID/address pairs emptied.
    pub fn sweep(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        let retention_ms = self.retention_ms;
        while self
            .expirations
            .first()
            .is_some_and(|(expires_at, _, _)| expires_at.saturating_add(retention_ms) < now)
        {
            let Some((expires_at, generation, key)) = self.expirations.pop_first() else {
                break;
            };
            if let Some(candidates) = self.entries.get_mut(&key) {
                candidates
                    .entries
                    .retain(|entry| entry.generation != generation);
                if candidates.omitted.is_some_and(|omitted| {
                    (omitted.expires_at, omitted.generation) == (expires_at, generation)
                }) {
                    candidates.omitted = None;
                }
                if candidates.entries.is_empty() && candidates.omitted.is_none() {
                    self.entries.remove(&key);
                }
            }
        }
        before - self.entries.len()
    }

    /// Returns the number of cached `(pid, address)` mappings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns true when no DNS evidence is retained.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn evict_one(&mut self) {
        while let Some((_, generation, key)) = self.expirations.pop_first() {
            if self.entries.get(&key).is_some_and(|entries| {
                entries
                    .omitted
                    .is_some_and(|omitted| omitted.generation == generation)
                    || entries
                        .entries
                        .iter()
                        .any(|entry| entry.generation == generation)
            }) {
                if let Some(entries) = self.entries.remove(&key) {
                    for entry in entries.entries {
                        self.expirations
                            .remove(&(entry.hint.expires_at, entry.generation, key));
                    }
                    if let Some(omitted) = entries.omitted {
                        self.expirations
                            .remove(&(omitted.expires_at, omitted.generation, key));
                    }
                }
                return;
            }
        }
    }
}

/// A DNS name as the hint map keys it: trimmed, without the root dot, lowercase.
#[must_use]
pub fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn normalizes_and_expires_hints() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(9, "Example.COM.", [ip], 100, 50);
        assert_eq!(hints.resolve(9, ip, 150), Some("example.com"));
        assert_eq!(hints.resolve(9, ip, 151), None);
        assert_eq!(hints.sweep(151), 1);
    }

    #[test]
    fn an_expired_hint_is_kept_for_the_retention_and_only_name_at_reads_it() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::with_retention(4, 1_000);
        hints.insert(9, "cached.test", [ip], 100, 50);

        assert_eq!(hints.resolve(9, ip, 151), None, "expired for the live API");
        assert_eq!(hints.sweep(1_150), 0, "still inside the retention");
        assert_eq!(
            hints.name_at(9, ip, 120, 130, 0),
            DnsHintAt::Live("cached.test")
        );
        assert_eq!(
            hints.name_at(9, ip, 900, 910, 0),
            DnsHintAt::Retained("cached.test"),
            "the process may still be using the address from its own cache"
        );
        assert_eq!(
            hints.name_at(9, ip, 10, 20, 0),
            DnsHintAt::Retained("cached.test"),
            "a single name recorded after the window is all that is known"
        );
        assert_eq!(
            hints.name_at(9, ip, 1_151, 1_160, 0),
            DnsHintAt::None,
            "past the retention it no longer answers, swept or not"
        );
        assert_eq!(hints.name_at(8, ip, 120, 130, 0), DnsHintAt::None);
        assert_eq!(hints.name_at(0, ip, 120, 130, 0), DnsHintAt::None);
        assert_eq!(hints.sweep(1_151), 1);
        assert!(hints.is_empty());
    }

    #[test]
    fn names_valid_in_the_window_decide_before_retained_ones() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::with_retention(4, 10_000);
        hints.insert(9, "old.test", [ip], 0, 100);
        hints.insert(9, "current.test", [ip], 500, 100);

        assert_eq!(
            hints.name_at(9, ip, 550, 560, 0),
            DnsHintAt::Live("current.test")
        );
        assert_eq!(
            hints.name_at(9, ip, 300, 310, 0),
            DnsHintAt::None,
            "two kept names and neither valid then: no telling which"
        );
        hints.insert(9, "also-current.test", [ip], 520, 100);
        assert_eq!(hints.name_at(9, ip, 550, 560, 0), DnsHintAt::Ambiguous);
        assert_eq!(
            hints.name_at(9, ip, 505, 510, 0),
            DnsHintAt::Live("current.test"),
            "the second name was not recorded until after the window"
        );
        assert_eq!(
            hints.name_at(9, ip, 505, 520, 0),
            DnsHintAt::Ambiguous,
            "a window that reaches the second name's recording includes it"
        );
    }

    #[test]
    fn hints_from_before_the_process_started_do_not_answer() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::with_retention(4, 10_000);
        hints.insert(9, "earlier-process.test", [ip], 100, 50);

        assert_eq!(
            hints.name_at(9, ip, 400, 410, 0),
            DnsHintAt::Retained("earlier-process.test")
        );
        assert_eq!(hints.name_at(9, ip, 400, 410, 200), DnsHintAt::None);
        hints.insert(9, "this-process.test", [ip], 300, 50);
        assert_eq!(
            hints.name_at(9, ip, 400, 410, 200),
            DnsHintAt::Retained("this-process.test")
        );
        assert_eq!(
            hints.name_at(9, ip, 320, 330, 200),
            DnsHintAt::Live("this-process.test")
        );
    }

    #[test]
    fn a_name_the_cap_discarded_keeps_name_at_from_answering() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::with_retention(1, 100_000);
        hints.insert(9, "discarded.test", [ip], 0, 1_000);
        for index in 0..10 {
            hints.insert(9, &format!("short-{index}.test"), [ip], 1, 10);
        }
        assert_eq!(
            hints.name_at(9, ip, 500, 510, 0),
            DnsHintAt::Ambiguous,
            "the discarded name was valid then, and so competes"
        );
        assert_eq!(
            hints.name_at(9, ip, 5_000, 5_010, 0),
            DnsHintAt::None,
            "eleven names were known and none was valid then"
        );
    }

    #[test]
    fn the_name_asked_for_just_before_the_window_is_the_nearest() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let rule = NearestHint {
            within_ms: 2_000,
            lead_ms: 750,
        };
        let mut hints = DnsHintMap::with_retention(4, 10_000);
        hints.insert(9, "earlier.test", [ip], 1_000, 60_000);
        hints.insert(9, "just-asked.test", [ip], 9_900, 60_000);

        assert_eq!(
            hints.name_at(9, ip, 10_000, 10_250, 0),
            DnsHintAt::Ambiguous
        );
        assert_eq!(
            hints.nearest_at(9, ip, 10_000, 10_250, 0, rule),
            Some("just-asked.test")
        );
        assert_eq!(
            hints.nearest_at(9, ip, 20_000, 20_250, 0, rule),
            None,
            "asked ten seconds before: the process may be reusing either name"
        );
        hints.insert(9, "asked-alongside.test", [ip], 9_950, 60_000);
        assert_eq!(
            hints.nearest_at(9, ip, 10_000, 10_250, 0, rule),
            None,
            "two names asked for together cannot be told apart"
        );
        assert_eq!(hints.nearest_at(8, ip, 10_000, 10_250, 0, rule), None);
    }

    #[test]
    fn the_nearest_name_ignores_hints_outside_the_window_and_before_the_process() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let rule = NearestHint {
            within_ms: 2_000,
            lead_ms: 750,
        };
        let mut hints = DnsHintMap::with_retention(4, 100_000);
        hints.insert(9, "expired.test", [ip], 9_000, 100);
        hints.insert(9, "valid.test", [ip], 8_000, 60_000);
        hints.insert(9, "asked-later.test", [ip], 30_000, 60_000);
        assert_eq!(
            hints.nearest_at(9, ip, 10_000, 10_250, 0, rule),
            Some("valid.test"),
            "an expired name and one asked for afterwards do not compete"
        );
        assert_eq!(
            hints.nearest_at(9, ip, 10_000, 10_250, 8_500, rule),
            None,
            "the only valid name was an earlier process's"
        );
    }

    #[test]
    fn a_name_the_cap_discarded_leaves_no_nearest_name() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let rule = NearestHint {
            within_ms: 2_000,
            lead_ms: 750,
        };
        let mut hints = DnsHintMap::with_retention(1, 100_000);
        hints.insert(9, "discarded.test", [ip], 0, 60_000);
        for index in 0..9 {
            hints.insert(9, &format!("short-{index}.test"), [ip], 1, 10);
        }
        hints.insert(9, "just-asked.test", [ip], 9_900, 60_000);
        assert_eq!(hints.nearest_at(9, ip, 10_000, 10_250, 0, rule), None);
    }

    #[test]
    fn multiple_domains_for_one_process_address_are_ambiguous() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(9, "first.test", [ip], 0, 100);
        hints.insert(9, "second.test", [ip], 1, 100);
        assert_eq!(hints.resolve(9, ip, 2), None);
    }

    #[test]
    fn older_domain_remains_when_a_newer_candidate_expires() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(9, "long-lived.test", [ip], 0, 100);
        hints.insert(9, "short-lived.test", [ip], 1, 10);
        assert_eq!(hints.resolve(9, ip, 12), Some("long-lived.test"));
        assert_eq!(hints.sweep(12), 0, "the PID/IP still has a live candidate");
        assert_eq!(hints.resolve(9, ip, 12), Some("long-lived.test"));
    }

    #[test]
    fn retains_ten_distinct_candidates_and_evicts_the_least_recently_recorded() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(1);
        for index in 0..10 {
            hints.insert(9, &format!("{index}.test"), [ip], index, 100);
        }
        let names = |hints: &DnsHintMap| {
            hints
                .resolve_candidates(9, ip, 12)
                .map(|hint| hint.domain.to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(&hints),
            (0..10)
                .rev()
                .map(|i| format!("{i}.test"))
                .collect::<Vec<_>>()
        );
        hints.insert(9, "0.TEST.", [ip], 10, 100);
        hints.insert(9, "10.test", [ip], 11, 100);
        assert_eq!(
            names(&hints),
            [
                "10.test", "0.test", "9.test", "8.test", "7.test", "6.test", "5.test", "4.test",
                "3.test", "2.test"
            ]
        );
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints.expirations.len(),
            11,
            "expiry indexes are bounded by ten candidates plus one omitted-evidence marker"
        );
    }

    #[test]
    fn repeated_normalized_names_refresh_only_their_own_ttl() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(1);
        hints.insert(9, "first.test", [ip], 0, 10);
        hints.insert(9, "second.test", [ip], 0, 20);
        hints.insert(9, " FIRST.TEST. ", [ip], 5, 100);
        assert_eq!(hints.resolve_candidates(9, ip, 6).count(), 2);
        assert_eq!(hints.resolve(9, ip, 21), Some("first.test"));
        assert_eq!(hints.sweep(21), 0);
        assert_eq!(hints.expirations.len(), 1);
        assert_eq!(hints.resolve(9, ip, 105), Some("first.test"));
        assert_eq!(hints.sweep(106), 1);
        assert!(hints.is_empty());
        assert!(hints.expirations.is_empty());
    }

    #[test]
    fn ambiguous_process_candidates_do_not_fall_back_to_shared_hints() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(3);
        hints.insert(0, "shared.test", [ip], 0, 100);
        hints.insert(9, "first.test", [ip], 0, 10);
        hints.insert(9, "second.test", [ip], 0, 10);
        assert_eq!(hints.resolve(9, ip, 1), None);
        assert!(
            hints
                .resolve_candidates(9, ip, 1)
                .all(|hint| hint.provenance == DnsHintProvenance::Process)
        );
        assert_eq!(hints.resolve(10, ip, 1), Some("shared.test"));
        assert_eq!(hints.resolve(9, ip, 11), Some("shared.test"));
        hints.insert(0, "another-shared.test", [ip], 1, 100);
        assert_eq!(hints.resolve(10, ip, 11), None);
    }

    #[test]
    fn capacity_eviction_removes_a_whole_pair_and_all_its_candidate_indexes() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(9, "first.test", [ip], 0, 10);
        hints.insert(9, "second.test", [ip], 0, 20);
        hints.insert(10, "other.test", [ip], 0, 100);
        hints.insert(11, "new.test", [ip], 0, 100);
        assert_eq!(hints.resolve_candidates(9, ip, 1).count(), 0);
        assert_eq!(hints.resolve(10, ip, 1), Some("other.test"));
        assert_eq!(hints.resolve(11, ip, 1), Some("new.test"));
        assert_eq!(hints.len(), 2);
        assert_eq!(hints.expirations.len(), 2);
        hints.clear();
        assert!(hints.is_empty());
        assert!(hints.expirations.is_empty());
    }

    #[test]
    fn an_unexpired_evicted_name_keeps_the_remaining_candidate_ambiguous() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(1);
        hints.insert(9, "evicted.test", [ip], 0, 1_000);
        for index in 0..9 {
            hints.insert(9, &format!("short-{index}.test"), [ip], 1, 10);
        }
        hints.insert(9, "retained.test", [ip], 2, 1_000);
        assert_eq!(
            hints.resolve(9, ip, 12),
            None,
            "a still-live evicted name makes the retained name uncertain"
        );
        assert_eq!(hints.resolve(9, ip, 1_000), None);
        assert_eq!(hints.resolve(9, ip, 1_001), Some("retained.test"));
    }

    #[test]
    fn an_unexpired_evicted_name_prevents_shared_fallback_when_retained_names_expire() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(0, "shared.test", [ip], 0, 2_000);
        hints.insert(9, "evicted.test", [ip], 0, 1_000);
        for index in 0..10 {
            hints.insert(9, &format!("short-{index}.test"), [ip], 1, 10);
        }
        hints.sweep(12);
        assert_eq!(hints.resolve(9, ip, 12), None);
        assert_eq!(hints.resolve(9, ip, 1_001), Some("shared.test"));
        hints.sweep(1_001);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints.expirations.len(), 1);
    }

    #[test]
    fn repeated_overflow_keeps_one_longest_expiry_marker_and_releases_it_on_eviction() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(1);
        for index in 0..100 {
            hints.insert(9, &format!("{index}.test"), [ip], 0, 1_000 - index);
            assert!(hints.expirations.len() <= 11);
        }
        assert_eq!(hints.resolve_candidates(9, ip, 950).count(), 0);
        assert!(hints.is_ambiguous(9, ip, 950));
        hints.sweep(950);
        assert_eq!(hints.expirations.len(), 1);
        hints.insert(10, "other.test", [ip], 950, 100);
        assert!(!hints.is_ambiguous(9, ip, 950));
        assert_eq!(hints.resolve(10, ip, 950), Some("other.test"));
        assert_eq!(hints.expirations.len(), 1);
    }

    #[test]
    fn a_reused_pid_forgets_only_the_earlier_process_hints() {
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let new = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let mut hints = DnsHintMap::new(8);
        hints.insert(9, "old.test", [old], 100, 10_000);
        hints.insert(9, "new.test", [new], 300, 10_000);
        hints.insert(10, "other.test", [old], 100, 10_000);
        assert_eq!(hints.forget_before(9, 200), 1);
        assert_eq!(hints.resolve(9, old, 400), None);
        assert_eq!(hints.resolve(9, new, 400), Some("new.test"));
        assert_eq!(hints.resolve(10, old, 400), Some("other.test"));
        assert_eq!(hints.expirations.len(), 2);
    }

    #[test]
    fn a_reused_pid_forgets_names_the_cap_discarded_before_its_start() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let mut hints = DnsHintMap::new(8);
        for index in 0..11 {
            hints.insert(9, &format!("old-{index}.test"), [ip], 100 + index, 10_000);
        }
        hints.insert(9, "new-process.test", [ip], 300, 10_000);
        hints.forget_before(9, 200);
        assert!(!hints.is_ambiguous(9, ip, 400));
        assert_eq!(hints.resolve(9, ip, 400), Some("new-process.test"));
        assert_eq!(hints.expirations.len(), 1);
    }

    #[test]
    fn names_the_cap_discarded_after_a_start_stay_ambiguous() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let mut hints = DnsHintMap::new(8);
        for index in 0..11 {
            hints.insert(9, &format!("new-{index}.test"), [ip], 300 + index, 10_000);
        }
        hints.forget_before(9, 200);
        assert!(hints.is_ambiguous(9, ip, 400));
    }

    #[test]
    fn system_hint_is_a_fallback() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(0, "system.test", [ip], 0, 100);
        assert_eq!(hints.resolve(55, ip, 1), Some("system.test"));
        let resolved = hints
            .resolve_with_provenance(55, ip, 1)
            .expect("shared hint");
        assert_eq!(resolved.domain, "system.test");
        assert_eq!(resolved.provenance, DnsHintProvenance::Shared);
    }

    #[test]
    fn exact_pid_hint_reports_process_provenance() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6));
        let mut hints = DnsHintMap::new(2);
        hints.insert(55, "process.test", [ip], 0, 100);

        let resolved = hints
            .resolve_with_provenance(55, ip, 1)
            .expect("process hint");
        assert_eq!(resolved.domain, "process.test");
        assert_eq!(resolved.provenance, DnsHintProvenance::Process);
    }

    #[test]
    fn expired_process_hint_does_not_mask_live_system_hint() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut hints = DnsHintMap::new(2);
        hints.insert(0, "system.test", [ip], 0, 100);
        hints.insert(55, "process.test", [ip], 0, 10);
        assert_eq!(hints.resolve(55, ip, 11), Some("system.test"));
    }

    #[test]
    fn capacity_evicts_earliest_live_expiration() {
        let first = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let second = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        let third = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3));
        let mut hints = DnsHintMap::new(2);
        hints.insert(1, "first.test", [first], 0, 10);
        hints.insert(1, "second.test", [second], 0, 20);
        hints.insert(1, "third.test", [third], 1, 30);
        assert_eq!(hints.resolve(1, first, 1), None);
        assert_eq!(hints.resolve(1, second, 1), Some("second.test"));
        assert_eq!(hints.resolve(1, third, 1), Some("third.test"));
    }

    #[test]
    fn refreshes_replace_expiration_index_entries() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let mut hints = DnsHintMap::new(2);
        for now in 0..10_000 {
            hints.insert(1, "refresh.test", [ip], now, 100);
        }
        assert_eq!(hints.len(), 1);
        assert_eq!(hints.expirations.len(), 1);
    }

    #[test]
    fn ipv4_mapped_answers_resolve_as_ipv4() {
        use std::net::Ipv6Addr;
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let mapped = IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
        let mut hints = DnsHintMap::new(8);
        hints.insert(4, "dual.test", [mapped], 0, 100);
        assert_eq!(hints.resolve(4, v4, 1), Some("dual.test"));
        assert_eq!(hints.resolve(4, mapped, 1), Some("dual.test"));
        assert_eq!(hints.len(), 1);
        let _ = Ipv6Addr::UNSPECIFIED;
    }
}
