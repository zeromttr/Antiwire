//! Versioned ownership markers for native firewall rows.

use data_encoding::BASE32_NOPAD;
use firew_core::{Direction, Error, ErrorKind, RuleKey};
use sha2::{Digest, Sha256};

const MARKER_VERSION: &str = "fw1";
const NAMESPACE_BYTES: usize = 10;
const NATIVE_OBJECT_VERSION: &str = "fwobj1";

/// Stable 16-character manager namespace derived from display configuration.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManagedNamespace(String);

impl ManagedNamespace {
    /// Derives a namespace from the manager and application names.
    #[must_use]
    pub fn derive(manager: &str, application: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(MARKER_VERSION.as_bytes());
        hasher.update([0]);
        hasher.update(manager.as_bytes());
        hasher.update([0]);
        hasher.update(application.as_bytes());
        let digest = hasher.finalize();
        Self(BASE32_NOPAD.encode(&digest[..NAMESPACE_BYTES]))
    }

    /// Returns the encoded namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns a stable, namespace-scoped token for a logical rule.
    ///
    /// Native containers such as ipset have short identifier limits. Hashing
    /// the namespace and the unsanitized key avoids collisions both between
    /// managers and between otherwise distinct keys such as `a-b` and `a_b`.
    #[must_use]
    pub fn native_object_token(&self, key: &RuleKey) -> String {
        let mut hasher = Sha256::new();
        hasher.update(NATIVE_OBJECT_VERSION.as_bytes());
        hasher.update([0]);
        hasher.update(self.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(key.as_str().as_bytes());
        let digest = hasher.finalize();
        BASE32_NOPAD.encode(&digest[..NAMESPACE_BYTES])
    }
}

/// Parsed marker attached to one native row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedMarker {
    /// Logical rule identity.
    pub key: RuleKey,
    /// Zero-based native part index.
    pub part: u16,
    /// Total number of native parts.
    pub total: u16,
}

impl ManagedMarker {
    /// Encodes a native ownership marker.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty set, an out-of-range part, or more than
    /// 1,295 parts.
    pub fn encode(&self, namespace: &ManagedNamespace) -> Result<String, Error> {
        if self.total == 0 || self.total > 1295 || self.part >= self.total {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                "invalid native marker part range",
            ));
        }
        Ok(format!(
            "{MARKER_VERSION}:{}:{}:{}{}",
            namespace.as_str(),
            self.key,
            encode_base36(self.part)?,
            encode_base36(self.total)?
        ))
    }

    /// Parses a marker belonging to `namespace`.
    ///
    /// Only the leading whitespace-delimited token is read, so a carrier field
    /// may append human-readable text after the marker — which is how the
    /// Windows backend keeps a rule's description both machine-parseable and
    /// legible.
    ///
    /// # Errors
    ///
    /// Returns an error when the marker is malformed, foreign, or internally
    /// inconsistent.
    pub fn parse(value: &str, namespace: &ManagedNamespace) -> Result<Self, Error> {
        let token = value.split_whitespace().next().unwrap_or_default();
        let mut fields = token.split(':');
        let version = fields.next();
        let encoded_namespace = fields.next();
        let key = fields.next();
        let parts = fields.next();
        if fields.next().is_some()
            || version != Some(MARKER_VERSION)
            || encoded_namespace != Some(namespace.as_str())
        {
            return Err(Error::new(
                ErrorKind::CorruptNativeState,
                "foreign or malformed native marker",
            ));
        }
        let parts = parts.ok_or_else(|| {
            Error::new(
                ErrorKind::CorruptNativeState,
                "native marker has invalid part encoding",
            )
        })?;
        let part_bytes: [u8; 4] = parts.as_bytes().try_into().map_err(|_| {
            Error::new(
                ErrorKind::CorruptNativeState,
                "native marker has invalid part encoding",
            )
        })?;
        let part = decode_base36([part_bytes[0], part_bytes[1]])?;
        let total = decode_base36([part_bytes[2], part_bytes[3]])?;
        let key = RuleKey::try_from(key.unwrap_or_default()).map_err(|error| {
            Error::new(
                ErrorKind::CorruptNativeState,
                format!("native marker has invalid key: {error}"),
            )
        })?;
        if total == 0 || part >= total {
            return Err(Error::new(
                ErrorKind::CorruptNativeState,
                "native marker part is outside its total",
            ));
        }
        Ok(Self { key, part, total })
    }
}

fn encode_base36(value: u16) -> Result<String, Error> {
    if value > 1295 {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            "base36 marker value exceeds two digits",
        ));
    }
    let high = digit(
        u8::try_from(value / 36)
            .map_err(|_| Error::new(ErrorKind::Internal, "base36 high digit conversion failed"))?,
    );
    let low = digit(
        u8::try_from(value % 36)
            .map_err(|_| Error::new(ErrorKind::Internal, "base36 low digit conversion failed"))?,
    );
    Ok(String::from_iter([high, low]))
}

fn decode_base36(bytes: [u8; 2]) -> Result<u16, Error> {
    let high = decode_digit(bytes[0])?;
    let low = decode_digit(bytes[1])?;
    Ok(u16::from(high) * 36 + u16::from(low))
}

fn digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        _ => char::from(b'A' + value - 10),
    }
}

fn decode_digit(value: u8) -> Result<u8, Error> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'A'..=b'Z' => Ok(value - b'A' + 10),
        _ => Err(Error::new(
            ErrorKind::CorruptNativeState,
            "invalid base36 marker digit",
        )),
    }
}

/// Numbers one logical rule's native rows and encodes each row's marker.
///
/// Every backend numbers a rule's rows `0..total`, and reconstruction relies on
/// that numbering being complete, so all of them count rows through this.
pub struct PartMarkers<'a> {
    key: &'a RuleKey,
    namespace: &'a ManagedNamespace,
    total: u16,
    next: u16,
}

impl<'a> PartMarkers<'a> {
    /// Starts numbering `rows` rows of `key`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::LimitExceeded`] when `rows` does not fit a marker's part
    /// count. `backend` names the backend in the message.
    pub fn new(
        backend: &str,
        key: &'a RuleKey,
        namespace: &'a ManagedNamespace,
        rows: usize,
    ) -> Result<Self, Error> {
        let total = u16::try_from(rows).map_err(|_| {
            Error::new(ErrorKind::LimitExceeded, format!("too many {backend} rows"))
                .with_logical_key(key)
        })?;
        Ok(Self {
            key,
            namespace,
            total,
            next: 0,
        })
    }

    /// How many rows the rule has.
    #[must_use]
    pub fn total(&self) -> u16 {
        self.total
    }

    /// The part number the next [`encode_next`](Self::encode_next) call encodes.
    #[must_use]
    pub fn next_part(&self) -> u16 {
        self.next
    }

    /// Encodes the marker for the next row.
    ///
    /// # Errors
    ///
    /// The error from [`ManagedMarker::encode`].
    pub fn encode_next(&mut self) -> Result<String, Error> {
        let marker = ManagedMarker {
            key: self.key.clone(),
            part: self.next,
            total: self.total,
        }
        .encode(self.namespace)?;
        self.next += 1;
        Ok(marker)
    }
}

/// The single directions a rule's native rows cover: inbound, outbound, or
/// both in that order.
#[must_use]
pub fn split_directions(direction: Direction) -> &'static [Direction] {
    match direction {
        Direction::Inbound => &[Direction::Inbound],
        Direction::Outbound => &[Direction::Outbound],
        Direction::Both => &[Direction::Inbound, Direction::Outbound],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_markers_number_rows_in_order_and_refuse_too_many() {
        let namespace = ManagedNamespace::derive("manager", "app");
        let key = RuleKey::try_from("numbered").expect("key");
        let mut markers = PartMarkers::new("test", &key, &namespace, 2).expect("two rows");
        assert_eq!(markers.total(), 2);
        for part in 0..2 {
            assert_eq!(markers.next_part(), part);
            let encoded = markers.encode_next().expect("marker");
            let parsed = ManagedMarker::parse(&encoded, &namespace).expect("parse");
            assert_eq!(
                (parsed.key.as_str(), parsed.part, parsed.total),
                ("numbered", part, 2)
            );
        }

        let error = PartMarkers::new("test", &key, &namespace, usize::from(u16::MAX) + 1)
            .err()
            .expect("more rows than a marker can number");
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }

    #[test]
    fn both_directions_split_inbound_first() {
        assert_eq!(
            split_directions(Direction::Both),
            &[Direction::Inbound, Direction::Outbound]
        );
        assert_eq!(
            split_directions(Direction::Outbound),
            &[Direction::Outbound]
        );
    }

    #[test]
    fn maximum_marker_fits_pf_label() {
        let namespace = ManagedNamespace::derive(&"m".repeat(64), &"a".repeat(64));
        let marker = ManagedMarker {
            key: RuleKey::try_from("K".repeat(32)).expect("valid key"),
            part: 255,
            total: 256,
        };
        let encoded = marker.encode(&namespace).expect("marker");
        assert!(encoded.len() < 64);
        assert_eq!(
            ManagedMarker::parse(&encoded, &namespace).expect("parse"),
            marker
        );
    }

    #[test]
    fn rejects_foreign_and_malformed_markers() {
        let namespace = ManagedNamespace::derive("manager", "application");
        let foreign = ManagedNamespace::derive("other", "application");
        let marker = ManagedMarker {
            key: RuleKey::try_from("rule").expect("valid key"),
            part: 0,
            total: 1,
        }
        .encode(&namespace)
        .expect("marker");

        assert_eq!(
            ManagedMarker::parse(&marker, &foreign)
                .expect_err("foreign namespace")
                .kind(),
            ErrorKind::CorruptNativeState
        );
        for malformed in [
            "",
            "fw1:SHORT:rule:0001",
            "fw1:AAAAAAAAAAAAAAAA:bad.key:0001",
            "fw1:AAAAAAAAAAAAAAAA:rule:0101",
            "fw1:AAAAAAAAAAAAAAAA:rule:0000",
            "fw2:AAAAAAAAAAAAAAAA:rule:0001",
            "fw1:AAAAAAAAAAAAAAAA:rule:0001:extra",
            "fw1:AAAAAAAAAAAAAAAA:rule:€x",
            "fw1:AAAAAAAAAAAAAAAA:rule:x€",
            "fw1:AAAAAAAAAAAAAAAA:rule:😀",
        ] {
            assert_eq!(
                ManagedMarker::parse(malformed, &namespace)
                    .expect_err("malformed marker")
                    .kind(),
                ErrorKind::CorruptNativeState
            );
        }
        let exact_ns = format!("fw1:{}:rule:€x", namespace.as_str());
        assert_eq!(
            ManagedMarker::parse(&exact_ns, &namespace)
                .expect_err("multibyte part field must not panic")
                .kind(),
            ErrorKind::CorruptNativeState
        );
    }

    #[test]
    fn rejects_duplicate_or_out_of_range_part_metadata_at_encoding() {
        let namespace = ManagedNamespace::derive("manager", "application");
        for marker in [
            ManagedMarker {
                key: RuleKey::try_from("rule").expect("valid key"),
                part: 0,
                total: 0,
            },
            ManagedMarker {
                key: RuleKey::try_from("rule").expect("valid key"),
                part: 1,
                total: 1,
            },
        ] {
            assert_eq!(
                marker.encode(&namespace).expect_err("invalid part").kind(),
                ErrorKind::InvalidRule
            );
        }
    }

    #[test]
    fn parses_a_marker_with_human_readable_text_after_it() {
        // The Windows backend stores the marker at the head of a rule's
        // description so the rest of the field can stay legible.
        let namespace = ManagedNamespace::derive("antiwire", "");
        let marker = ManagedMarker {
            key: RuleKey::try_from("antiwire-ax-rules-1").expect("valid key"),
            part: 0,
            total: 2,
        };
        let encoded = marker.encode(&namespace).expect("encode");

        let carried = format!("{encoded} Antiwire AX country block (part 1 of 2)");
        let parsed = ManagedMarker::parse(&carried, &namespace).expect("parse with suffix");
        assert_eq!(parsed, marker);

        // The bare marker must still parse, so rules written before the move
        // are not orphaned.
        assert_eq!(
            ManagedMarker::parse(&encoded, &namespace).expect("parse bare"),
            marker
        );
    }

    #[test]
    fn a_renamed_rule_does_not_parse_as_ours() {
        let namespace = ManagedNamespace::derive("antiwire", "");
        for foreign in [
            "Block Netflix",
            "",
            "   ",
            "fw1:WRONGNAMESPACE00:antiwire-ax-rules-1:0002",
            "fw1:antiwire-ax-rules-1:0002",
        ] {
            assert!(
                ManagedMarker::parse(foreign, &namespace).is_err(),
                "{foreign:?} should not be recognised as a managed marker"
            );
        }
    }

    #[test]
    fn native_object_tokens_include_namespace_and_unsanitized_key() {
        let first = ManagedNamespace::derive("first", "");
        let second = ManagedNamespace::derive("second", "");
        let hyphen = RuleKey::try_from("a-b").expect("key");
        let underscore = RuleKey::try_from("a_b").expect("key");

        assert_ne!(
            first.native_object_token(&hyphen),
            first.native_object_token(&underscore)
        );
        assert_ne!(
            first.native_object_token(&hyphen),
            second.native_object_token(&hyphen)
        );
        assert_eq!(first.native_object_token(&hyphen).len(), 16);
    }
}
