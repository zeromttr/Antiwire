//! Compact approximate suffix membership for downloaded domain blocklists.
//!
//! An ordinary lookup performs at most six approximate `BinaryFuse16` probes.
//! The union bound gives a combined false-positive probability below 0.01%.
//! Tables containing entries with more than six labels use additional
//! approximate prechecks confirmed by a sorted exact-hash side table, so deep
//! names cannot increase the false-positive probability. Construction is
//! fallible and separate from atomic publication; a failed build leaves the
//! currently published snapshot unchanged.

use std::sync::Arc;

use arc_swap::ArcSwap;
use xorf::{BinaryFuse16, Filter};

use crate::blocklist_line::normalized_blocklist_domain;
use crate::hash::reverse_hash_pair;

const MAX_BLOCKLIST_ENTRIES: usize = 5_000_000;
const BLOCKLIST_TOO_LARGE: &str = "blocklist exceeds maximum entry count";

/// Immutable published blocklist state.
pub(crate) struct BlocklistSnapshot {
    filter: Option<BinaryFuse16>,
    unique_count: usize,
    deep_hashes: Box<[u64]>,
    /// Whether any entry is a single label (e.g. `localhost`). When false,
    /// lookups skip the bare-TLD suffix probe that could never match.
    has_single_label_entries: bool,
    /// Exact hash-to-source relationships used only after a combined hit.
    named_attribution: NamedAttributionSnapshot,
}

struct NamedAttributionSnapshot {
    names: Box<[String]>,
    hashes: Box<[u64]>,
    name_indices: Box<[u32]>,
}

#[derive(Default)]
struct MatchedNameIndices {
    inline: u128,
    overflow: Vec<u32>,
}

impl BlocklistSnapshot {
    pub(crate) fn empty() -> Self {
        Self {
            filter: None,
            unique_count: 0,
            deep_hashes: Box::new([]),
            has_single_label_entries: false,
            named_attribution: NamedAttributionSnapshot::empty(),
        }
    }

    #[inline]
    fn contains_suffix(&self, filter: &BinaryFuse16, hash: u64, label_count: usize) -> bool {
        contains_suffix(filter, &self.deep_hashes, hash, label_count)
    }
}

impl NamedAttributionSnapshot {
    fn empty() -> Self {
        Self {
            names: Box::new([]),
            hashes: Box::new([]),
            name_indices: Box::new([]),
        }
    }

    fn append_name_indices(&self, hash: u64, matches: &mut MatchedNameIndices) {
        let Ok(mut start) = self.hashes.binary_search(&hash) else {
            return;
        };
        while start > 0 && self.hashes[start - 1] == hash {
            start -= 1;
        }
        let mut end = start + 1;
        while end < self.hashes.len() && self.hashes[end] == hash {
            end += 1;
        }
        matches.extend_from_slice(&self.name_indices[start..end]);
    }
}

impl MatchedNameIndices {
    fn extend_from_slice(&mut self, indices: &[u32]) {
        for &index in indices {
            if index < u128::BITS {
                self.inline |= 1_u128 << index;
            } else {
                self.overflow.push(index);
            }
        }
    }

    fn into_names(mut self, names: &[String]) -> Vec<String> {
        self.overflow.sort_unstable();
        self.overflow.dedup();
        let inline_count =
            usize::try_from(self.inline.count_ones()).expect("u128 population count fits in usize");
        let mut matched_names = Vec::with_capacity(inline_count + self.overflow.len());

        while self.inline != 0 {
            let index = self.inline.trailing_zeros();
            self.inline &= self.inline - 1;
            matched_names.push(
                names[usize::try_from(index).expect("inline source index fits in usize")].clone(),
            );
        }
        matched_names.extend(self.overflow.into_iter().map(|index| {
            names[usize::try_from(index).expect("source index fits in usize")].clone()
        }));
        matched_names
    }
}

#[inline]
fn contains_suffix(
    filter: &BinaryFuse16,
    deep_hashes: &[u64],
    hash: u64,
    label_count: usize,
) -> bool {
    filter.contains(&hash) && (label_count <= 6 || deep_hashes.binary_search(&hash).is_ok())
}

#[inline]
const fn no_deeper_entries(has_deep_entries: bool, label_count: usize) -> bool {
    !has_deep_entries && label_count > 6
}

struct NamedListAccum {
    name: String,
    hashes: Vec<u64>,
}

/// Mutable, single-owner input for a blocklist snapshot.
pub struct BlocklistBuilder {
    hashes: Vec<u64>,
    deep_hashes: Vec<u64>,
    has_single_label_entries: bool,
    named_lists: Vec<NamedListAccum>,
    max_entries: usize,
    limit_exceeded: bool,
}

impl BlocklistBuilder {
    #[must_use]
    pub fn new(expected_count: usize) -> Self {
        Self::with_entry_limit(expected_count, MAX_BLOCKLIST_ENTRIES)
    }

    fn with_entry_limit(expected_count: usize, max_entries: usize) -> Self {
        // Match the caller's bounded catalog estimate so a normal large list
        // does not cross a Vec growth boundary during construction.
        let capacity = expected_count.max(1024).min(max_entries);
        Self {
            hashes: Vec::with_capacity(capacity),
            deep_hashes: Vec::new(),
            has_single_label_entries: false,
            named_lists: Vec::new(),
            max_entries,
            limit_exceeded: false,
        }
    }

    #[cfg(test)]
    fn with_max_entries(expected_count: usize, max_entries: usize) -> Self {
        Self::with_entry_limit(expected_count, max_entries)
    }

    /// Adds a valid normalized domain and reports whether it was accepted.
    pub fn add_domain(&mut self, domain: &str) -> bool {
        self.add_from_list("", domain)
    }

    /// Adds a domain and attributes it to `list_name` when that name is non-empty.
    pub fn add_from_list(&mut self, list_name: &str, domain: &str) -> bool {
        let Some(trimmed) = normalized_blocklist_domain(domain) else {
            return false;
        };
        if self.hashes.len() >= self.max_entries {
            self.limit_exceeded = true;
            return false;
        }

        let label_count = trimmed.bytes().filter(|byte| *byte == b'.').count() + 1;
        let hash = reverse_hash_pair(&trimmed);
        push_hash(
            &mut self.hashes,
            &mut self.deep_hashes,
            &mut self.has_single_label_entries,
            hash,
            label_count,
        );
        if !list_name.is_empty() {
            let list = named_list_mut(&mut self.named_lists, list_name);
            list.hashes.push(hash);
        }
        true
    }

    /// Deduplicates the accumulated hashes and constructs an immutable filter.
    ///
    /// # Errors
    ///
    /// Returns an error when the binary-fuse graph cannot be constructed.
    pub fn prepare(self) -> Result<PreparedBlocklist, &'static str> {
        self.prepare_with(|hashes| BinaryFuse16::try_from(hashes))
    }

    fn prepare_with(
        mut self,
        construct: impl FnOnce(&[u64]) -> Result<BinaryFuse16, &'static str>,
    ) -> Result<PreparedBlocklist, &'static str> {
        if self.limit_exceeded {
            return Err(BLOCKLIST_TOO_LARGE);
        }
        self.hashes.sort_unstable();
        self.hashes.dedup();
        self.deep_hashes.sort_unstable();
        self.deep_hashes.dedup();

        let unique_count = self.hashes.len();
        let filter = if self.hashes.is_empty() {
            None
        } else {
            Some(construct(self.hashes.as_slice())?)
        };

        let relationship_count = self.named_lists.iter().map(|list| list.hashes.len()).sum();
        let mut names = Vec::with_capacity(self.named_lists.len());
        let mut relationships = Vec::with_capacity(relationship_count);
        for mut list in self.named_lists {
            list.hashes.sort_unstable();
            list.hashes.dedup();
            if list.hashes.is_empty() {
                continue;
            }
            let name_index = u32::try_from(names.len()).map_err(|_| "too many named lists")?;
            names.push(list.name);
            relationships.extend(list.hashes.into_iter().map(|hash| (hash, name_index)));
        }
        relationships.sort_unstable();
        let mut named_hashes = Vec::with_capacity(relationships.len());
        let mut name_indices = Vec::with_capacity(relationships.len());
        for (hash, name_index) in relationships {
            named_hashes.push(hash);
            name_indices.push(name_index);
        }

        Ok(PreparedBlocklist(BlocklistSnapshot {
            filter,
            unique_count,
            deep_hashes: self.deep_hashes.into_boxed_slice(),
            has_single_label_entries: self.has_single_label_entries,
            named_attribution: NamedAttributionSnapshot {
                names: names.into_boxed_slice(),
                hashes: named_hashes.into_boxed_slice(),
                name_indices: name_indices.into_boxed_slice(),
            },
        }))
    }
}

fn push_hash(
    hashes: &mut Vec<u64>,
    deep_hashes: &mut Vec<u64>,
    has_single_label_entries: &mut bool,
    hash: u64,
    label_count: usize,
) {
    hashes.push(hash);
    if label_count > 6 {
        deep_hashes.push(hash);
    }
    if label_count == 1 {
        *has_single_label_entries = true;
    }
}

fn named_list_mut<'a>(lists: &'a mut Vec<NamedListAccum>, name: &str) -> &'a mut NamedListAccum {
    if let Some(index) = lists.iter().position(|list| list.name == name) {
        return &mut lists[index];
    }
    lists.push(NamedListAccum {
        name: name.to_owned(),
        hashes: Vec::new(),
    });
    lists.last_mut().expect("named list just inserted")
}

/// Fully constructed immutable state ready for atomic publication.
pub struct PreparedBlocklist(BlocklistSnapshot);

impl PreparedBlocklist {
    #[cfg(test)]
    #[must_use]
    fn unique_count(&self) -> usize {
        self.0.unique_count
    }
}

/// Allocation-free suffix-hash lookup over an atomically published filter.
pub(crate) struct BlocklistEngine {
    live: ArcSwap<BlocklistSnapshot>,
}

impl Default for BlocklistEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocklistEngine {
    #[must_use]
    pub fn new() -> Self {
        Self {
            live: ArcSwap::from_pointee(BlocklistSnapshot::empty()),
        }
    }

    pub(crate) fn publish(&self, prepared: PreparedBlocklist) {
        self.live.store(Arc::new(prepared.0));
    }

    #[must_use]
    pub(crate) fn load_full(&self) -> Arc<BlocklistSnapshot> {
        self.live.load_full()
    }

    #[cfg(test)]
    pub(crate) fn load_blocklist<I>(&self, domains: I)
    where
        I: IntoIterator,
        I::Item: AsRef<str>,
    {
        let domains = domains.into_iter();
        let (lower, upper) = domains.size_hint();
        let mut builder = BlocklistBuilder::new(upper.unwrap_or(lower).max(1024));
        for domain in domains {
            builder.add_domain(domain.as_ref());
        }
        self.publish(builder.prepare().expect("prepare test blocklist"));
    }

    #[cfg(test)]
    pub(crate) fn clear_blocklist(&self) {
        self.live.store(Arc::new(BlocklistSnapshot::empty()));
    }

    /// Number of unique domain entries in the currently live snapshot.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.live.load().unique_count
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_domain_blocked(&self, domain: &str) -> bool {
        self.lookup::<false>(domain)
    }

    /// Lookup for callers that guarantee `domain` is already lowercase ASCII.
    #[must_use]
    pub(crate) fn is_normalized_domain_blocked(&self, domain: &str) -> bool {
        self.lookup::<true>(domain)
    }

    /// Named lists that contain `domain` or one of its suffixes.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn matching_blocklists(&self, domain: &str) -> Vec<String> {
        self.matching::<false>(domain)
    }

    /// Attribution for callers that guarantee `domain` is lowercase ASCII.
    #[must_use]
    pub(crate) fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        self.matching::<true>(domain)
    }

    fn lookup<const NORMALIZED: bool>(&self, domain: &str) -> bool {
        self.live.load().lookup::<NORMALIZED>(domain)
    }

    fn matching<const NORMALIZED: bool>(&self, domain: &str) -> Vec<String> {
        self.live.load().matching::<NORMALIZED>(domain)
    }
}

impl BlocklistSnapshot {
    pub(crate) fn lookup<const NORMALIZED: bool>(&self, domain: &str) -> bool {
        if domain.is_empty() {
            return false;
        }

        let Some(filter) = &self.filter else {
            return false;
        };
        let has_deep_entries = !self.deep_hashes.is_empty();

        let mut found = false;
        for_each_suffix_hash::<NORMALIZED>(domain, |hash, label_count, is_tld| {
            if is_tld && !self.has_single_label_entries {
                return true;
            }
            if no_deeper_entries(has_deep_entries, label_count) {
                return false;
            }
            if self.contains_suffix(filter, hash, label_count) {
                found = true;
                return false;
            }
            true
        });
        found
    }

    pub(crate) fn matching<const NORMALIZED: bool>(&self, domain: &str) -> Vec<String> {
        if domain.is_empty() {
            return Vec::new();
        }

        if self.named_attribution.names.is_empty() {
            return Vec::new();
        }

        let mut matched = MatchedNameIndices::default();
        for_each_suffix_hash::<NORMALIZED>(domain, |hash, _, _| {
            self.named_attribution
                .append_name_indices(hash, &mut matched);
            true
        });
        matched.into_names(&self.named_attribution.names)
    }
}

/// Walks suffix hashes right-to-left. `visit` receives `(hash, label_count, is_tld)`
/// and returns `false` to stop.
fn for_each_suffix_hash<const NORMALIZED: bool>(
    domain: &str,
    mut visit: impl FnMut(u64, usize, bool) -> bool,
) {
    let bytes = domain.as_bytes();
    let mut h1 = 2_166_136_261_u32;
    let mut h2 = 5_381_u32;
    let mut at_tld_boundary = true;
    let mut label_count = 1_usize;

    for i in (0..bytes.len()).rev() {
        let c = if !NORMALIZED && bytes[i].is_ascii_uppercase() {
            bytes[i].to_ascii_lowercase()
        } else {
            bytes[i]
        };
        h1 = h1.wrapping_mul(16_777_619) ^ u32::from(c);
        h2 = h2
            .wrapping_shl(5)
            .wrapping_add(h2)
            .wrapping_add(u32::from(c));

        if i == 0 || bytes[i - 1] == b'.' {
            let is_tld = at_tld_boundary;
            at_tld_boundary = false;
            let hash = crate::hash::suffix_hash_at_boundary(h1, h2);
            if !visit(hash, label_count, is_tld) {
                return;
            }
            label_count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        for_each_suffix_hash, no_deeper_entries, BlocklistBuilder, BlocklistEngine,
        MatchedNameIndices, BLOCKLIST_TOO_LARGE,
    };
    use crate::hash::reverse_hash_pair;
    use xorf::Filter;

    #[test]
    fn prepared_blocklist_deduplicates_domains() {
        let mut builder = BlocklistBuilder::new(3);
        builder.add_domain("tracker.example");
        builder.add_domain("TRACKER.EXAMPLE.");
        builder.add_domain("*.tracker.example");

        let prepared = builder.prepare().expect("prepare blocklist");

        assert_eq!(prepared.unique_count(), 1);
    }

    #[test]
    fn builder_rejects_impossible_domain_names() {
        let mut builder = BlocklistBuilder::new(4);
        builder.add_domain("valid.example");
        builder.add_domain("bad..example");
        builder.add_domain("embedded.*.example");
        builder.add_domain(&format!("{}.example", "a".repeat(64)));

        let prepared = builder.prepare().expect("prepare blocklist");

        assert_eq!(prepared.unique_count(), 1);
    }

    #[test]
    fn builder_reserves_the_bounded_large_list_estimate() {
        let builder = BlocklistBuilder::new(1_048_577);

        assert!(builder.hashes.capacity() >= 1_048_577);
    }

    #[test]
    fn builder_rejects_entries_past_the_aggregate_limit() {
        let mut builder = BlocklistBuilder::with_max_entries(2, 2);
        assert!(builder.add_from_list("first", "one.example"));
        assert!(builder.add_from_list("second", "two.example"));
        assert!(!builder.add_from_list("third", "three.example"));

        assert_eq!(builder.prepare().err(), Some(BLOCKLIST_TOO_LARGE));
    }

    #[test]
    fn ordinary_tables_stop_after_six_approximate_probes_for_deep_domains() {
        let domain = format!("{}.allowed.example", vec!["x"; 100].join("."));
        let mut probes = 0;

        for_each_suffix_hash::<true>(&domain, |_, label_count, _| {
            if no_deeper_entries(false, label_count) {
                return false;
            }
            probes += 1;
            true
        });

        assert_eq!(probes, 6);
    }

    #[test]
    fn matched_name_indices_spill_without_losing_order_or_deduplication() {
        let names: Vec<String> = (0..130).map(|index| format!("source{index}")).collect();
        let mut matched = MatchedNameIndices::default();
        matched.extend_from_slice(&[129, 2, 129, 1]);

        assert_eq!(
            matched.into_names(&names),
            vec![
                "source1".to_owned(),
                "source2".to_owned(),
                "source129".to_owned()
            ]
        );
    }

    #[test]
    fn publishing_prepared_blocklist_replaces_live_snapshot() {
        let engine = BlocklistEngine::new();
        let mut first = BlocklistBuilder::new(1);
        first.add_domain("first.a.b.c.d.e.example");
        engine.publish(first.prepare().expect("prepare first"));
        assert_eq!(engine.len(), 1);

        let mut second = BlocklistBuilder::new(2);
        second.add_domain("second.a.b.c.d.e.example");
        second.add_domain("another.example");
        engine.publish(second.prepare().expect("prepare second"));

        assert_eq!(engine.len(), 2);
        assert!(engine.is_domain_blocked("second.a.b.c.d.e.example"));
        assert!(engine.is_domain_blocked("another.example"));
    }

    #[test]
    fn failed_preparation_leaves_live_snapshot_unchanged() {
        let engine = BlocklistEngine::new();
        let mut first = BlocklistBuilder::new(1);
        first.add_domain("live.a.b.c.d.e.example");
        engine.publish(first.prepare().expect("prepare live snapshot"));

        let mut replacement = BlocklistBuilder::new(1);
        replacement.add_domain("replacement.a.b.c.d.e.example");
        let failure = replacement.prepare_with(|_| Err("injected construction failure"));

        assert_eq!(failure.err(), Some("injected construction failure"));
        assert_eq!(engine.len(), 1);
        assert!(engine.is_domain_blocked("live.a.b.c.d.e.example"));
    }

    #[test]
    fn successful_preparation_is_invisible_until_publication() {
        let engine = BlocklistEngine::new();
        let mut live = BlocklistBuilder::new(1);
        live.add_domain("live.a.b.c.d.e.example");
        engine.publish(live.prepare().expect("prepare live snapshot"));

        let mut replacement = BlocklistBuilder::new(1);
        replacement.add_domain("replacement.a.b.c.d.e.example");
        let prepared = replacement.prepare().expect("prepare replacement");
        assert_eq!(engine.len(), 1);
        assert!(engine.is_domain_blocked("live.a.b.c.d.e.example"));

        engine.publish(prepared);
        assert_eq!(engine.len(), 1);
        assert!(engine.is_domain_blocked("replacement.a.b.c.d.e.example"));
    }

    #[test]
    fn deep_suffix_entries_have_no_false_negatives() {
        let engine = BlocklistEngine::new();
        let mut builder = BlocklistBuilder::new(1);
        builder.add_domain("blocked.a.b.c.d.e.example");
        engine.publish(builder.prepare().expect("prepare blocklist"));

        assert!(engine.is_domain_blocked("blocked.a.b.c.d.e.example"));
    }

    #[test]
    fn deep_filter_false_positive_is_rejected() {
        let mut builder = BlocklistBuilder::new(1);
        builder.add_domain("blocked.a.b.c.d.e.example");
        let prepared = builder.prepare().expect("prepare blocklist");
        let snapshot = &prepared.0;
        let filter = snapshot.filter.as_ref().expect("nonempty filter");
        let false_positive = (0..2_000_000_u64)
            .find(|hash| filter.contains(hash) && snapshot.deep_hashes.binary_search(hash).is_err())
            .expect("find deterministic deep false positive");

        assert!(!snapshot.contains_suffix(filter, false_positive, 7));
        assert!(snapshot.contains_suffix(filter, false_positive, 6));
    }

    #[test]
    fn filter_has_no_false_negatives_for_inserted_domains() {
        let mut builder = BlocklistBuilder::new(10_000);
        for i in 0..10_000 {
            builder.add_domain(&format!("d{i}.ads.example"));
        }
        let engine = BlocklistEngine::new();
        engine.publish(builder.prepare().expect("prepare blocklist"));

        for i in 0..10_000 {
            assert!(engine.is_domain_blocked(&format!("sub.d{i}.ads.example")));
        }
    }

    #[test]
    fn blocklist_matches_suffixes() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["adserver.net", "tracker.co.uk"]);

        assert!(engine.is_domain_blocked("adserver.net"));
        assert!(engine.is_domain_blocked("sub.adserver.net"));
        assert!(engine.is_domain_blocked("deep.sub.adserver.net"));
        assert!(engine.is_domain_blocked("TRACKER.CO.UK"));
    }

    #[test]
    fn wildcard_prefix_is_stripped_on_insert() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["*.malicious.com"]);

        assert!(engine.is_domain_blocked("malicious.com"));
        assert!(engine.is_domain_blocked("ads.malicious.com"));
    }

    #[test]
    fn inserted_suffix_is_found() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["blocked.test"]);

        assert!(engine.is_domain_blocked("sub.blocked.test"));
    }

    #[test]
    fn len_reports_unique_live_domains() {
        let engine = BlocklistEngine::new();
        assert!(engine.is_empty());
        assert_eq!(engine.len(), 0);

        engine.load_blocklist(["adserver.net", "tracker.co.uk", "adserver.net"]);
        assert_eq!(engine.len(), 2);

        engine.clear_blocklist();
        assert!(engine.is_empty());
    }

    #[test]
    fn empty_blocklist_matches_nothing() {
        let engine = BlocklistEngine::new();
        assert!(!engine.is_domain_blocked("example.com"));

        engine.load_blocklist(["blocked.test"]);
        engine.clear_blocklist();
        assert!(!engine.is_domain_blocked("blocked.test"));
    }

    #[test]
    fn single_label_entries_still_match() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["localhost", "tracker.example"]);

        assert!(engine.is_domain_blocked("localhost"));
        assert!(engine.is_domain_blocked("sub.localhost"));
        assert!(engine.is_domain_blocked("LOCALHOST"));
    }

    #[test]
    fn normalized_lookup_matches_case_insensitive_lookup() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["adserver.net", "localhost"]);

        assert!(engine.is_normalized_domain_blocked("sub.adserver.net"));
        assert!(engine.is_normalized_domain_blocked("localhost"));
    }

    #[test]
    fn untagged_domains_block_without_list_names() {
        let engine = BlocklistEngine::new();
        engine.load_blocklist(["ads.example"]);

        assert!(engine.is_domain_blocked("ads.example"));
        assert!(engine.matching_blocklists("ads.example").is_empty());
    }

    #[test]
    fn matching_blocklists_reports_each_source_in_insertion_order() {
        let mut builder = BlocklistBuilder::new(4);
        builder.add_from_list("hagezi_light", "ads.example");
        builder.add_from_list("hagezi_tif", "malware.example");
        builder.add_from_list("hagezi_tif", "ads.example");
        builder.add_from_list("system_hosts", "local.test");
        let engine = BlocklistEngine::new();
        engine.publish(builder.prepare().expect("prepare named lists"));

        assert_eq!(
            engine.matching_blocklists("sub.ads.example"),
            vec!["hagezi_light".to_owned(), "hagezi_tif".to_owned()]
        );
        assert_eq!(
            engine.matching_normalized_blocklists("malware.example"),
            vec!["hagezi_tif".to_owned()]
        );
        assert_eq!(
            engine.matching_blocklists("LOCAL.TEST"),
            vec!["system_hosts".to_owned()]
        );
        assert!(engine.matching_blocklists("unlisted.example").is_empty());
    }

    #[test]
    fn named_attribution_rejects_filter_false_positives() {
        let mut builder = BlocklistBuilder::new(1);
        builder.add_from_list("hagezi_light", "blocked.example");
        let prepared = builder.prepare().expect("prepare named list");
        let filter = prepared.0.filter.as_ref().expect("combined filter");
        let false_positive = (0..2_000_000)
            .map(|index| format!("allowed{index}.example"))
            .find(|domain| filter.contains(&reverse_hash_pair(domain)))
            .expect("find deterministic named-filter false positive");

        let engine = BlocklistEngine::new();
        engine.publish(prepared);

        assert!(engine.matching_blocklists(&false_positive).is_empty());
    }
}
