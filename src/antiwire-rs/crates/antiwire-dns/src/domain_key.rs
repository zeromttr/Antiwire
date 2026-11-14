//! Heap-free owned domain name for the response-cache key.
//!
//! Every query builds a key, so the key's string must not cost a heap
//! allocation. A wire-format name is at most 255 bytes and its presentation
//! form is one byte shorter, so an inline buffer covers every valid name;
//! only Hickory's escaped presentation of a label with unusual bytes can grow
//! past that, and it spills to the heap.

use hickory_proto::rr::Name;
use smallvec::SmallVec;
use std::borrow::Borrow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::Deref;

/// Longest presentation-form name without a trailing dot: the 255-byte wire
/// limit less the root byte and one length byte that no dot replaces.
const INLINE_CAPACITY: usize = Name::MAX_LENGTH - 2;

/// A normalized (lowercase, no trailing dot) domain name owned by a cache key.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct DomainKey(SmallVec<[u8; INLINE_CAPACITY]>);

impl DomainKey {
    fn new() -> Self {
        Self::default()
    }

    fn from_str(value: &str) -> Self {
        Self(SmallVec::from_slice(value.as_bytes()))
    }

    fn push(&mut self, value: char) {
        self.push_str(value.encode_utf8(&mut [0; 4]));
    }

    fn push_str(&mut self, value: &str) {
        self.0.extend_from_slice(value.as_bytes());
    }

    fn make_ascii_lowercase(&mut self) {
        self.0.make_ascii_lowercase();
    }

    pub(crate) fn as_str(&self) -> &str {
        // Construction and mutation accept only UTF-8 strings/chars; ASCII
        // case conversion preserves UTF-8, and the byte buffer stays private.
        std::str::from_utf8(&self.0).expect("domain key contains valid UTF-8")
    }

    pub(crate) fn spilled(&self) -> bool {
        self.0.spilled()
    }
}

impl Deref for DomainKey {
    type Target = str;

    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for DomainKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl Hash for DomainKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl fmt::Debug for DomainKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), formatter)
    }
}

impl fmt::Display for DomainKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl PartialEq<&str> for DomainKey {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Normalizes `name` without allocating for any valid unescaped name.
///
/// Labels made only of hostname-safe bytes are copied straight from Hickory's
/// label storage; anything else defers to `Name::to_ascii` so the key matches
/// what [`Name::from_ascii`] will parse back for prefetch.
pub(crate) fn from_name(name: &Name, needs_lowercase: bool) -> DomainKey {
    let mut key = DomainKey::new();
    for (index, label) in name.iter().enumerate() {
        let Some(label) = plain_label(label) else {
            return from_presentation(name.to_ascii());
        };
        if index > 0 {
            key.push('.');
        }
        key.push_str(label);
    }
    if needs_lowercase {
        key.make_ascii_lowercase();
    }
    key
}

/// Builds a key from a presentation-form name, dropping one trailing dot.
pub(crate) fn from_presentation(mut name: String) -> DomainKey {
    if name.ends_with('.') {
        name.pop();
    }
    name.make_ascii_lowercase();
    // Copy into the inline buffer whenever the presentation fits.
    DomainKey::from_str(&name)
}

/// Bytes a key holds outside its own `size_of`, for cache weighting.
pub(crate) fn heap_bytes(key: &DomainKey) -> usize {
    if key.spilled() {
        key.len()
    } else {
        0
    }
}

/// `label` as text when Hickory's ASCII presentation of it is its own bytes.
///
/// Mirrors the unescaped set in `hickory_proto::rr::domain::Label::write_ascii`:
/// alphanumerics and `_` anywhere, `-` except first, `*` only first.
fn plain_label(label: &[u8]) -> Option<&str> {
    let (&first, rest) = label.split_first()?;
    let plain = (first.is_ascii_alphanumeric() || first == b'_' || first == b'*')
        && rest
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-');
    // Every byte checked above is ASCII, so this cannot fail.
    plain.then(|| std::str::from_utf8(label).ok()).flatten()
}

#[cfg(test)]
mod tests {
    use std::hash::{Hash, Hasher};

    use super::*;

    fn to_ascii_normalized(name: &Name) -> String {
        let mut ascii = name.to_ascii();
        if ascii.ends_with('.') {
            ascii.pop();
        }
        ascii.make_ascii_lowercase();
        ascii
    }

    #[test]
    fn plain_names_stay_inline_and_match_hickory_presentation() {
        for text in [
            "example.test.",
            "ExAmPlE.TeSt.",
            "_dmarc.example.test.",
            "*.wildcard.test.",
            "xn--e1afmkfd.xn--p1ai.",
            "a.",
            ".",
        ] {
            let name = Name::from_ascii(text).expect("name");
            let key = from_name(&name, true);
            assert!(!key.spilled(), "{text}");
            assert_eq!(key.as_str(), to_ascii_normalized(&name), "{text}");
        }
    }

    #[test]
    fn lowercase_is_applied_only_when_requested() {
        let name = Name::from_ascii("ExAmPlE.TeSt.").expect("name");
        assert_eq!(from_name(&name, false), "ExAmPlE.TeSt");
        assert_eq!(from_name(&name, true), "example.test");
    }

    #[test]
    fn escaped_labels_fall_back_to_hickory_presentation() {
        // A dot inside a label, a space, and a leading dash all escape in
        // Hickory's ASCII form, so the raw-bytes fast path must step aside.
        let mut name = Name::from_labels([
            b"we.ird".as_slice(),
            b"a b".as_slice(),
            b"-dash".as_slice(),
            b"test".as_slice(),
        ])
        .expect("labels");
        name.set_fqdn(true);
        let key = from_name(&name, true);
        assert!(key.contains("\\."), "escapes survive: {key}");
        assert_eq!(key.as_str(), to_ascii_normalized(&name));
        assert!(
            !key.spilled(),
            "escaped forms still fit the wire limit here"
        );
    }

    #[test]
    fn longest_valid_name_is_inline() {
        let label = "a".repeat(63);
        let text = format!("{label}.{label}.{label}.{}.", "b".repeat(61));
        let name = Name::from_ascii(&text).expect("253-byte name");
        let key = from_name(&name, true);
        assert!(!key.spilled());
        assert_eq!(key.len(), INLINE_CAPACITY);
    }

    #[test]
    fn oversized_presentation_spills_to_the_heap_without_changing_equality() {
        let long = "x".repeat(INLINE_CAPACITY + 1);
        let heap = from_presentation(long.clone());
        assert!(heap.spilled());
        assert_eq!(heap_bytes(&heap), long.len());
        assert_eq!(heap, from_presentation(long.clone()));
    }

    #[test]
    fn equality_and_hash_follow_the_string() {
        use std::collections::hash_map::DefaultHasher;

        let hash = |value: &dyn Fn(&mut DefaultHasher)| {
            let mut hasher = DefaultHasher::new();
            value(&mut hasher);
            hasher.finish()
        };
        let a = from_presentation("example.test".to_owned());
        let b = from_presentation("Example.Test.".to_owned());
        assert_eq!(a, b);
        assert_ne!(a, from_presentation("example.tests".to_owned()));
        assert_eq!(
            hash(&|hasher| a.hash(hasher)),
            hash(&|hasher| "example.test".hash(hasher)),
            "a key hashes like the plain string it holds"
        );
        assert_eq!(heap_bytes(&a), 0);
    }

    #[test]
    fn heap_keys_support_string_lookup_and_preserve_unicode() {
        use std::collections::HashMap;

        let text = format!("{}é", "x".repeat(INLINE_CAPACITY));
        let key = from_presentation(text.clone());
        assert!(key.spilled());
        assert_eq!(heap_bytes(&key), text.len());
        assert_eq!(key.clone().to_string(), text);
        let keys = HashMap::from([(key, 7)]);
        assert_eq!(keys.get(text.as_str()), Some(&7));
    }
}
