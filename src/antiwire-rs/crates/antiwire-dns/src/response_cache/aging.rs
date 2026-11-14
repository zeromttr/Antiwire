//! Ageing of cached record TTLs and RFC 2308 negative-TTL derivation.

use std::sync::Arc;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};

use antiwire_tuning::{
    DNS_MAX_UPSTREAM_TTL_SECONDS, DNS_MIN_UPSTREAM_TTL_SECONDS, DNS_NEGATIVE_ANSWER_TTL_SECONDS,
    DNS_STALE_ANSWER_TTL_SECONDS,
};

use super::entry::CachedAnswer;

#[derive(Debug)]
pub(super) struct AgedBucket {
    elapsed_secs: u32,
    serving_stale: bool,
    sections: Arc<AgedSections>,
}

/// Record sections of a cached answer with TTLs counted down for one serve.
///
/// Only the three record sections are copied; the cached header, question,
/// and OPT record are read through the shared parse tree.
#[derive(Debug, Clone)]
pub(crate) struct AgedSections {
    pub(crate) answers: Vec<Record>,
    pub(crate) authorities: Vec<Record>,
    pub(crate) additionals: Vec<Record>,
}

impl super::ResponseCache {
    /// Counts the record TTLs of `message` down by the time `cached` has spent
    /// in the cache.
    ///
    /// Returns `None` within the first second, when the stored records can be
    /// served exactly as they are; only then is nothing copied. The caller
    /// overlays the client-specific transaction ID and RD bit itself and
    /// supplies the original request question to hickory's response builder,
    /// so neither the header nor the question section is ever cloned.
    #[must_use]
    pub(crate) fn age_sections(
        cached: &CachedAnswer,
        message: &Message,
    ) -> Option<Arc<AgedSections>> {
        let elapsed = u32::try_from(cached.cached_at.elapsed().as_secs()).unwrap_or(u32::MAX);
        if elapsed == 0 {
            return None;
        }
        let serving_stale = std::time::Instant::now() >= cached.fresh_until;
        {
            let guard = cached.aged.lock();
            if let Some(bucket) = guard.as_ref() {
                if bucket.elapsed_secs == elapsed && bucket.serving_stale == serving_stale {
                    return Some(Arc::clone(&bucket.sections));
                }
            }
        }
        let negative =
            message.metadata.response_code == ResponseCode::NXDomain || message.answers.is_empty();
        let mut sections = AgedSections {
            answers: message.answers.clone(),
            authorities: message.authorities.clone(),
            additionals: message.additionals.clone(),
        };
        // Answers define positive-entry freshness and the SOA defines
        // negative-entry freshness. Preserve those semantic records at a
        // one-second floor when the configured minimum cache TTL is longer
        // than their original TTL; auxiliary sections do not get extended.
        // A stale serve keeps every section, its expired records at the
        // RFC 8767 stale TTL.
        let (answers, authorities, additionals) = if serving_stale {
            (Expired::Stale, Expired::Stale, Expired::Stale)
        } else if negative {
            (Expired::Floor, Expired::Floor, Expired::Drop)
        } else {
            (Expired::Floor, Expired::Drop, Expired::Drop)
        };
        age_records(&mut sections.answers, elapsed, answers);
        age_records(&mut sections.authorities, elapsed, authorities);
        age_records(&mut sections.additionals, elapsed, additionals);
        let sections = Arc::new(sections);
        *cached.aged.lock() = Some(AgedBucket {
            elapsed_secs: elapsed,
            serving_stale,
            sections: Arc::clone(&sections),
        });
        Some(sections)
    }

    /// Cache lifetime for `message`, in seconds.
    ///
    /// A positive answer is held for its shortest answer TTL. An answerless one —
    /// NXDOMAIN or NODATA — is held for the RFC 2308 §5 negative TTL instead: the
    /// lesser of the authority SOA's own TTL and its MINIMUM field, so a zone
    /// that publishes a shorter negative TTL than the limit here is not
    /// over-cached. Either kind is held no longer than [`ttl_ceiling`] allows,
    /// which is also how long an answer that names no lifetime is held.
    #[must_use]
    pub(crate) fn message_ttl_seconds(message: &Message) -> u32 {
        let answer_ttl = message.answers.iter().map(|record| record.ttl).min();
        let negative_ttl = negative_ttl_seconds(message);
        let ttl = if message.metadata.response_code == ResponseCode::NXDomain {
            match (answer_ttl, negative_ttl) {
                (Some(answer), Some(negative)) => Some(answer.min(negative)),
                (answer, negative) => answer.or(negative),
            }
        } else {
            answer_ttl.or(negative_ttl)
        };
        let ceiling = ttl_ceiling(message);
        ttl.unwrap_or(ceiling)
            .clamp(DNS_MIN_UPSTREAM_TTL_SECONDS as u32, ceiling)
    }
}

/// Whether `message` says the name, or a record of the asked type, does not exist.
pub(super) fn is_negative(message: &Message) -> bool {
    message.metadata.response_code == ResponseCode::NXDomain || message.answers.is_empty()
}

/// The longest `message` is held, in seconds: far less for a negative answer than for
/// records. See `DNS_NEGATIVE_ANSWER_TTL_SECONDS` for why.
fn ttl_ceiling(message: &Message) -> u32 {
    if is_negative(message) {
        DNS_NEGATIVE_ANSWER_TTL_SECONDS
    } else {
        DNS_MAX_UPSTREAM_TTL_SECONDS as u32
    }
}

/// Caps every record TTL at the longest this cache holds the answer.
///
/// The cap bounds how long an entry stays fresh, but clients cache what the
/// records say. Uncapped, a one-day TTL would keep an answer in a client for a
/// day after this resolver refreshed it or a block took effect, and a zone's
/// half-hour negative TTL would keep "does not exist" there as long. TTL is a
/// fixed-width field, so the encoded size does not change.
pub(super) fn cap_record_ttls(message: &mut Message) {
    let max = ttl_ceiling(message);
    for record in message
        .answers
        .iter_mut()
        .chain(message.authorities.iter_mut())
        .chain(message.additionals.iter_mut())
    {
        record.ttl = record.ttl.min(max);
    }
}

/// RFC 2308 §5 negative-caching TTL: `min(SOA.ttl, SOA.MINIMUM)`.
fn negative_ttl_seconds(message: &Message) -> Option<u32> {
    message
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
}

/// What [`age_records`] does with a record whose TTL has run out.
#[derive(Clone, Copy)]
enum Expired {
    /// Removes it.
    Drop,
    /// Keeps it at one second: it is held past its TTL by the configured
    /// minimum cache TTL, and the entry is still fresh.
    Floor,
    /// Keeps it at the RFC 8767 §4 stale TTL. The RFC requires more than
    /// zero and recommends 30 s, so clients do not re-ask every second.
    Stale,
}

fn age_records(records: &mut Vec<Record>, elapsed: u32, expired: Expired) {
    if let Expired::Floor | Expired::Stale = expired {
        let expired_ttl = match expired {
            Expired::Stale => DNS_STALE_ANSWER_TTL_SECONDS,
            _ => 1,
        };
        for record in records {
            // TTL 0 asks not to be cached at all, so it stays 0.
            if record.ttl > 0 {
                record.ttl = match record.ttl.saturating_sub(elapsed) {
                    0 => expired_ttl,
                    remaining => remaining,
                };
            }
        }
    } else {
        // The entry can remain fresh because the answer section determines its
        // lifetime while glue/authority data has a shorter independent TTL.
        // Never extend those auxiliary records to the answer's expiry.
        records.retain_mut(|record| {
            if record.ttl <= elapsed {
                return false;
            }
            record.ttl -= elapsed;
            true
        });
    }
}
