//! Naming a connection's remote address, recording new domains, and
//! buffering DNS answers for one batched write per flush.

use std::net::IpAddr;
use std::sync::atomic::Ordering;

use antiwire_store::{DnsCacheEntry, DomainEvidence, NewConnectionLog, INFERRED_SUFFIX};
use netmetrics_core::FlowKey;

use time::OffsetDateTime;
use tracing::warn;

use super::hint_scopes::{HintedName, Opening};
use super::FlowProcessor;
use super::Naming;
use crate::domain_stats::{executable_key, LookupOutcome};
use crate::sanitize;

/// How long after a connection opened a hint recorded before it can still
/// arrive. A hint is stamped when its answer was given. A DNS-Client event
/// then waits for its session's flush timer, which is a second, and a stub
/// answer for the owner of its client's socket to be found.
///
/// In a 15-minute capture the slowest of 425 DNS-Client hints took 1,058 ms,
/// one in five waited out the whole timer, and no stub hint took over 3 ms.
/// That was one capture of a lightly loaded machine, so this is over three
/// times the slowest. Too short a wait lets a late hint find the name already
/// final; too long only keeps a name correctable a little longer. The domain
/// telemetry reports the delays (`hint_delay_max_ms`, `hints_late`).
pub(super) const HINTS_ARRIVE_WITHIN_MS: u64 = 3_500;

/// A connection's name as one lookup judged it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Judged {
    /// The name: with [`INFERRED_SUFFIX`] when inferred, empty when nothing
    /// names the address.
    pub(super) domain: String,
    /// The hints decided, by a name or by names that competed. Otherwise the
    /// answer is whatever the address-only tables hold.
    from_hints: bool,
    /// How far the answer can be relied on.
    pub(super) naming: Naming,
}

impl Judged {
    /// The name a row should have, given the name `written` to it and this
    /// later judgment.
    ///
    /// When the judgment `replaces`, what the hints say now stands in place
    /// of what was written, whichever is the stronger. The address-only
    /// tables say nothing of the moment the connection opened, so their
    /// answer displaces only a confirmed name, whose hint has since been
    /// withdrawn. In every other case the stronger name is kept, so that a
    /// blank name turns inferred once per connection and only confirmation
    /// replaces it.
    pub(super) fn over(&self, written: &str, replaces: bool) -> String {
        let hint_withdrawn = antiwire_store::domain_evidence(written) == DomainEvidence::Confirmed;
        if replaces && (self.from_hints || hint_withdrawn) {
            self.domain.clone()
        } else {
            antiwire_store::prefer_dst_domain(written, &self.domain)
        }
    }
}

/// DNS answers buffered between flushes before SQLite is contacted.
///
/// One transaction per DNS response ran inline on the tracker's event loop.
/// Answers now accumulate here and are written in one batch on the flush tick
/// (or early once this cap is reached).
pub(super) const DNS_CACHE_PENDING_CAP: usize = 8_192;

impl FlowProcessor {
    /// [`Self::name_connection`] for a connection that opens now, by a
    /// process whose executable and start time are unknown.
    #[cfg(test)]
    pub(super) fn lookup_domain(&self, flow_pid: u32, ip: &IpAddr) -> String {
        self.name_connection(flow_pid, 0, ip, Opening::at(netmetrics_core::unix_now_ms()))
            .domain
    }

    /// Gives `log` the name a lookup as of `opening` leaves it with, and
    /// returns what the lookup said of its answer. See
    /// [`FlowProcessor::enrich_connection_log`].
    pub(super) fn name_log(
        &self,
        key: &FlowKey,
        flow_pid: u32,
        app_path: &str,
        opening: Opening,
        replaces: bool,
        log: &mut NewConnectionLog,
    ) -> Naming {
        let prior = antiwire_store::domain_evidence(&log.dst_domain);
        if !replaces && prior == DomainEvidence::Confirmed {
            // Nothing is stronger than the name the row has.
            return Naming {
                complete_at_ms: complete_at(opening),
                lasting: true,
            };
        }
        let executable = executable_key(app_path);
        let judged = self.name_connection(flow_pid, executable, &key.remote_addr, opening);
        let chosen = judged.over(&log.dst_domain, replaces);
        log.replace_domain = chosen != antiwire_store::prefer_dst_domain(&log.dst_domain, &chosen);
        log.dst_domain = chosen;
        let now = antiwire_store::domain_evidence(&log.dst_domain);
        if log.replace_domain {
            self.domain_stats.record_correction(false, now);
        }
        if prior == DomainEvidence::None && now == DomainEvidence::Inferred {
            self.domain_stats.record_first_inferred(
                flow_pid,
                executable,
                key.remote_addr,
                netmetrics_core::unix_now_ms(),
            );
        }
        if prior == DomainEvidence::Inferred && now == DomainEvidence::Confirmed {
            self.domain_upgrades.fetch_add(1, Ordering::Relaxed);
        }
        judged.naming
    }

    /// The name of `ip` for a connection of `flow_pid`, which runs the
    /// executable with key `executable` and opened at `opening`, and how far
    /// that answer can be relied on.
    pub(super) fn name_connection(
        &self,
        flow_pid: u32,
        executable: u64,
        ip: &IpAddr,
        opening: Opening,
    ) -> Judged {
        let (domain, outcome, competing) =
            self.name_connection_at(flow_pid, executable, ip, opening);
        self.domain_stats
            .record_lookup(flow_pid, *ip, outcome, netmetrics_core::unix_now_ms());
        // A confirmed name is final once every hint from the opening is in.
        // So are the names that competed then: they are a fact about the
        // past, later evidence cannot add to them, and a hint dropped from
        // memory must not leave one looking like the only name there was.
        let confirmed = antiwire_store::domain_evidence(&domain) == DomainEvidence::Confirmed;
        Judged {
            domain,
            from_hints: outcome.decided_by_hints(),
            naming: Naming {
                complete_at_ms: complete_at(opening),
                lasting: confirmed || competing,
            },
        }
    }

    fn name_connection_at(
        &self,
        flow_pid: u32,
        executable: u64,
        ip: &IpAddr,
        opening: Opening,
    ) -> (String, LookupOutcome, bool) {
        if let Some(named) = self.hinted_name(flow_pid, executable, ip, opening) {
            return named;
        }
        let (domain, outcome) = self.address_name(ip);
        (domain, outcome, false)
    }

    /// The name the hints give `ip` as they stood when the connection opened:
    /// those for its process, then its application, then no process. With it,
    /// the outcome to count and whether the answer came of the process's own
    /// names competing. `None` when no hint names the address.
    fn hinted_name(
        &self,
        flow_pid: u32,
        executable: u64,
        ip: &IpAddr,
        opening: Opening,
    ) -> Option<(String, LookupOutcome, bool)> {
        let hints = self.dns_hints.read();
        let clean = |domain: &str| sanitize::text(domain, sanitize::MAX_DOMAIN_CHARS);
        let inferred = |domain: &str| format!("{}{INFERRED_SUFFIX}", clean(domain));
        Some(match hints.name(flow_pid, executable, *ip, opening) {
            HintedName::Process(domain) => (clean(domain), LookupOutcome::ProcessHint, false),
            HintedName::Application(domain) => {
                (clean(domain), LookupOutcome::ApplicationHint, false)
            }
            HintedName::RetainedProcess(domain) => {
                (clean(domain), LookupOutcome::RetainedProcessHint, false)
            }
            HintedName::RetainedApplication(domain) => {
                (clean(domain), LookupOutcome::RetainedApplicationHint, false)
            }
            HintedName::Likeliest(domain) => (inferred(domain), LookupOutcome::NearestHint, true),
            HintedName::Shared(domain) => (inferred(domain), LookupOutcome::SharedHint, false),
            // Names that competed when the connection opened make a single
            // global fallback misleading.
            HintedName::Ambiguous => (String::new(), LookupOutcome::Ambiguous, true),
            HintedName::SharedAmbiguous => (String::new(), LookupOutcome::Ambiguous, false),
            HintedName::Unknown => return None,
        })
    }

    /// The name the address-only tables give `ip`, which is always an
    /// inference: they do not say who asked.
    fn address_name(&self, ip: &IpAddr) -> (String, LookupOutcome) {
        // Answers buffered for the next store flush are still valid mappings.
        // Checking them here keeps lookups coherent with what was just observed
        // without forcing a synchronous write.
        if let Some(entry) = self.pending_dns.lock().get(ip) {
            let domain = sanitize::text(&entry.domain, sanitize::MAX_DOMAIN_CHARS);
            return (format!("{domain}{INFERRED_SUFFIX}"), LookupOutcome::Pending);
        }

        // Fall back to global SQLite store and label as inferred
        let id = ip.to_string();
        match self.store.get_dns_cache(&id) {
            Ok(Some(entry))
                if antiwire_store::dns_inference_eligible(
                    entry.last_seen,
                    OffsetDateTime::now_utc(),
                ) =>
            {
                let domain = sanitize::text(&entry.domain, sanitize::MAX_DOMAIN_CHARS);
                (format!("{domain}{INFERRED_SUFFIX}"), LookupOutcome::Store)
            }
            Ok(_) => (String::new(), LookupOutcome::Unresolved),
            Err(error) => {
                warn!(error = %error, ip = %id, "dns cache lookup failed");
                (String::new(), LookupOutcome::Unresolved)
            }
        }
    }

    pub(super) fn maybe_queue_new_domain(
        &self,
        log: &NewConnectionLog,
        app_name: &str,
        app_path: &str,
    ) {
        let domain = sanitize::trimmed(
            strip_inferred_suffix(&log.dst_domain),
            sanitize::MAX_DOMAIN_CHARS,
        );
        if domain.is_empty() {
            return;
        }
        // Deduplicate in memory first. A domain sighting used to compile and run
        // an `INSERT OR IGNORE` for every closed flow, even for a name seen
        // hundreds of times; the seen-set makes that a one-time cost per domain.
        if self.seen_domains.lock().put(domain.clone(), ()).is_some() {
            return;
        }
        match self.store.record_domain_sighting(&domain, log.last_seen) {
            Ok(true) => self
                .siem
                .queue_new_domain_event(&domain, app_name, app_path),
            Ok(false) => {}
            Err(error) => {
                // Let a later sighting retry after a transient failure.
                self.seen_domains.lock().pop(&domain);
                warn!(error = %error, domain = %domain, "domain sighting failed");
            }
        }
    }

    pub(super) fn record_dns_resolution(&self, query: &str, answers: &[String]) {
        // DNS names are attacker-influenced: a crafted name must not be able to
        // inject log lines or bloat the cache row.
        let query = sanitize::trimmed(query, sanitize::MAX_DOMAIN_CHARS);
        if query.is_empty() {
            return;
        }

        // Canonicalize for consistent keys (notably IPv6 spellings), drop
        // non-addresses, and coalesce per IP so a repeated answer writes once.
        // The batch is committed from `flush_dns_cache` rather than inline, so a
        // DNS storm cannot run a transaction per response on the event loop.
        let now = OffsetDateTime::now_utc();
        let mut shed = 0;
        let mut named = Vec::new();
        let overflow = {
            let mut pending = self.pending_dns.lock();
            // While the store is failing, a full buffer waits for the flush tick
            // rather than retrying the whole batch inline on every answer.
            let backing_off = self.dns_cache_failing.load(Ordering::Relaxed);
            for answer in answers {
                let Ok(ip) = answer.parse::<IpAddr>() else {
                    continue;
                };
                if backing_off
                    && pending.len() >= DNS_CACHE_PENDING_CAP
                    && !pending.contains_key(&ip)
                {
                    shed += 1;
                    continue;
                }
                pending.insert(
                    ip,
                    DnsCacheEntry {
                        id: ip.to_string(),
                        domain: query.clone(),
                        last_seen: now,
                    },
                );
                named.push(ip);
            }
            (!backing_off && pending.len() >= DNS_CACHE_PENDING_CAP)
                .then(|| pending.drain().map(|(_, entry)| entry).collect::<Vec<_>>())
        };
        self.note_dns_answers_shed(shed);
        if let Some(entries) = overflow {
            self.write_dns_cache_entries(entries);
        }
        // Buffered or written, the answers are now where a lookup reads them.
        self.note_named(named);
    }

    /// Persists buffered DNS answers. Called on the tracker's flush tick and once
    /// at shutdown; a failed write is requeued up to the pending cap.
    pub(crate) fn flush_dns_cache(&self) {
        let entries: Vec<DnsCacheEntry> = {
            let mut pending = self.pending_dns.lock();
            if pending.is_empty() {
                return;
            }
            pending.drain().map(|(_, entry)| entry).collect()
        };
        self.write_dns_cache_entries(entries);
    }

    fn write_dns_cache_entries(&self, entries: Vec<DnsCacheEntry>) {
        if entries.is_empty() {
            return;
        }
        let Err(error) = self.store.upsert_dns_cache_batch(&entries) else {
            self.dns_cache_failing.store(false, Ordering::Relaxed);
            return;
        };
        warn!(
            error = %error,
            entries = entries.len(),
            "dns cache batch upsert failed"
        );
        self.dns_cache_failing.store(true, Ordering::Relaxed);
        // Requeue what fits, so a transient database failure does not drop a
        // whole batch. An address observed again since the drain keeps its newer
        // answer.
        let mut shed = 0;
        {
            let mut pending = self.pending_dns.lock();
            for entry in entries {
                let Ok(ip) = entry.id.parse::<IpAddr>() else {
                    continue;
                };
                if pending.contains_key(&ip) {
                    continue;
                }
                if pending.len() >= DNS_CACHE_PENDING_CAP {
                    shed += 1;
                    continue;
                }
                pending.insert(ip, entry);
            }
        }
        self.note_dns_answers_shed(shed);
    }

    fn note_dns_answers_shed(&self, count: u64) {
        if count == 0 {
            return;
        }
        let total = self.domain_stats.record_dns_answers_shed(count);
        if (total - count).checked_ilog2() != total.checked_ilog2() {
            warn!(
                shed = total,
                "dns cache buffer is full while the store is failing; dropping answers"
            );
        }
    }
}

/// When every hint recorded before `opening` will have arrived, in Unix
/// epoch milliseconds.
fn complete_at(opening: Opening) -> u64 {
    opening.at_ms.saturating_add(HINTS_ARRIVE_WITHIN_MS)
}

pub(super) fn strip_inferred_suffix(domain: &str) -> &str {
    domain.trim_end_matches(INFERRED_SUFFIX)
}

/// Returns true when `name` needs sanitation before it is stored or correlated.
///
/// DNS names are not supposed to contain control characters or exceed the wire
/// limit, but the name reaches this crate from parsed packets and kernel events,
/// so both conditions are re-checked here.
pub(super) fn needs_dns_sanitization(name: &str) -> bool {
    name.chars().count() > sanitize::MAX_DOMAIN_CHARS || sanitize::has_control_chars(name)
}
