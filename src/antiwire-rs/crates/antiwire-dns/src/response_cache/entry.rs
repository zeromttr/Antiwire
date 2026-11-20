//! Cached answer representation, admission, and expiry.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use moka::Expiry;
use parking_lot::Mutex;

use antiwire_tuning::{
    DNS_MIN_PREFETCH_TTL, DNS_PREFETCH_FRACTION, DNS_RESPONSE_CACHE_BYTE_CAP,
    DNS_RESPONSE_CACHE_HARD_CAP, DNS_RESPONSE_CACHE_MAX_ENTRY_BYTES, DNS_SERVE_STALE_GRACE,
};

use crate::answers::AnswerHint;
use crate::messages::encode_message;
use crate::upstream::UpstreamAnswer;
use crate::Result;

use super::aging::{cap_record_ttls, is_negative, AgedBucket};
use super::key::CacheKey;

/// Cached DNS answer with freshness metadata.
#[derive(Debug, Clone)]
pub(crate) struct CachedAnswer {
    /// Parsed response the cache-hit path encodes from.
    pub(crate) parsed_message: Arc<Message>,
    /// Encoded response size used for admission, cache weighting, and response
    /// buffer sizing without retaining a second copy of the DNS payload.
    pub(crate) encoded_len: usize,
    pub(crate) fresh_until: Instant,
    pub(crate) stale_until: Instant,
    pub(crate) prefetch_at: Instant,
    pub(crate) serve_stale: bool,
    /// When the answer entered the cache; used to count TTLs down on serve.
    pub(crate) cached_at: Instant,
    /// False for answers too large to store. They are still returned to the
    /// client; they are just never retained.
    pub(crate) cacheable: bool,
    /// Reused TTL-aged sections for repeated hits in the same elapsed-second
    /// bucket. Shared across clones of this entry and bounded by cache eviction.
    pub(super) aged: Arc<Mutex<Option<AgedBucket>>>,
    /// The address hint for serves in the first second, which send the stored
    /// sections unaged (see `ResponseCache::answer_hint`). Shared across clones.
    pub(super) unaged_hint: Arc<OnceLock<Option<AnswerHint>>>,
}

/// Result of a synchronous cache probe.
#[derive(Debug, Clone)]
pub(crate) enum CacheProbe {
    Fresh(CachedAnswer),
    Stale(CachedAnswer),
    Miss,
}

/// Moka expiry: an entry lives until the end of its stale window.
pub(super) struct AnswerExpiry;

/// Time left in `value`'s stale window, zero once it has passed.
///
/// Never `None`: to moka that clears the expiry, keeping a past-due entry
/// until size-based eviction.
fn time_to_live(value: &CachedAnswer, now: Instant) -> Duration {
    value.stale_until.saturating_duration_since(now)
}

impl Expiry<CacheKey, CachedAnswer> for AnswerExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &CachedAnswer,
        current_time: Instant,
    ) -> Option<Duration> {
        Some(time_to_live(value, current_time))
    }

    fn expire_after_read(
        &self,
        _key: &CacheKey,
        value: &CachedAnswer,
        current_time: Instant,
        _duration_until_expiry: Option<Duration>,
        _last_modified_at: Instant,
    ) -> Option<Duration> {
        Some(time_to_live(value, current_time))
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &CachedAnswer,
        current_time: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(time_to_live(value, current_time))
    }
}

/// Conservatively estimates the resident memory of one entry while also
/// translating the configured hard entry cap into a minimum per-entry weight.
/// Moka has one scalar capacity, so this enforces the byte budget and ensures
/// even tiny responses cannot exceed the entry-count bound.
pub(super) fn cache_entry_weight(key: &CacheKey, value: &CachedAnswer) -> u32 {
    let byte_cap = usize::try_from(DNS_RESPONSE_CACHE_BYTE_CAP).unwrap_or(usize::MAX);
    let hard_cap = usize::try_from(DNS_RESPONSE_CACHE_HARD_CAP)
        .unwrap_or(1)
        .max(1);
    let minimum_weight = byte_cap.saturating_add(hard_cap - 1) / hard_cap;

    // DNS compression can make the parsed ownership tree materially larger
    // than the packet. Three times the encoded size plus owned key/fixed
    // storage is intentionally conservative without requiring a hot-path tree
    // walk for exact heap accounting.
    // One extra encoded-size budget covers the bounded aged-section snapshot.
    let parsed_estimate = value.encoded_len.saturating_mul(4);
    let structural = std::mem::size_of::<CacheKey>()
        .saturating_add(std::mem::size_of::<CachedAnswer>())
        .saturating_add(crate::domain_key::heap_bytes(&key.domain));
    let bytes = parsed_estimate
        .saturating_add(structural)
        .max(minimum_weight)
        .max(1);
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

impl super::ResponseCache {
    /// Builds a cached entry from an upstream `Message`.
    pub(crate) fn entry_from_message(message: &Message, negative: bool) -> Result<CachedAnswer> {
        let encoded_len = encode_message(message)?.len();
        let mut message = message.clone();
        cap_record_ttls(&mut message);
        Ok(Self::entry(
            encoded_len,
            Self::message_ttl_seconds(&message),
            negative,
            Arc::new(message),
        ))
    }

    /// Moves a normal upstream answer into the cache without cloning its parse
    /// tree or re-encoding it when the transport supplied its encoded size.
    /// NXDOMAIN and empty answers are cached as negative.
    pub(crate) fn entry_from_upstream(answer: UpstreamAnswer) -> Result<CachedAnswer> {
        let UpstreamAnswer {
            mut message,
            encoded_len,
        } = answer;
        cap_record_ttls(&mut message);
        let negative = is_negative(&message);
        let ttl_seconds = Self::message_ttl_seconds(&message);
        let encoded_len = match encoded_len {
            Some(encoded_len) => encoded_len,
            None => encode_message(&message)?.len(),
        };
        Ok(Self::entry(
            encoded_len,
            ttl_seconds,
            negative,
            Arc::new(message),
        ))
    }

    fn entry(
        encoded_len: usize,
        ttl_seconds: u32,
        negative: bool,
        parsed_message: Arc<Message>,
    ) -> CachedAnswer {
        let cacheable = encoded_len <= DNS_RESPONSE_CACHE_MAX_ENTRY_BYTES as usize;

        let now = Instant::now();
        let fresh_for = Duration::from_secs(u64::from(ttl_seconds));
        let fresh_until = now + fresh_for;
        let stale_until = if negative {
            fresh_until
        } else {
            fresh_until + DNS_SERVE_STALE_GRACE
        };
        // Below the prefetch floor there is no useful lead time to compute, so the
        // entry simply expires and the next query re-fetches on the miss path.
        // Collapsing `prefetch_at` to `now` instead would make *every* fresh hit
        // on a short-TTL entry schedule a background refresh, turning the cache
        // into a continuous upstream refresh loop for exactly the popular
        // low-TTL domains it should be absorbing.
        let prefetch_at = if fresh_for >= DNS_MIN_PREFETCH_TTL {
            let lead = Duration::from_secs_f64(fresh_for.as_secs_f64() * DNS_PREFETCH_FRACTION);
            fresh_until.checked_sub(lead).unwrap_or(now)
        } else {
            fresh_until
        };
        CachedAnswer {
            parsed_message,
            encoded_len,
            fresh_until,
            stale_until,
            prefetch_at,
            serve_stale: !negative,
            cached_at: now,
            cacheable,
            aged: Arc::new(Mutex::new(None)),
            unaged_hint: Arc::new(OnceLock::new()),
        }
    }
}
