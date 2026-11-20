//! RFC 8914 Extended DNS Errors (EDE).
//!
//! Provides standardized diagnostic codes for EDNS OPT pseudo-records, enabling
//! clients (e.g. browsers, `dig +ede`) to distinguish between policy blocks,
//! content filtering, and network errors.

use hickory_proto::rr::rdata::opt::EdnsOption;

/// RFC 8914 Option Code for Extended DNS Error.
pub(crate) const EDNS_OPTION_CODE_EDE: u16 = 15;

/// EDE 3: Stale Answer (served from cache past its TTL, RFC 8767).
pub(crate) const EDE_STALE_ANSWER: u16 = 3;
/// EDE 13: Cached Error (a SERVFAIL answered from a cached failure, RFC 9520).
pub(crate) const EDE_CACHED_ERROR: u16 = 13;
/// EDE 15: Blocked (The request was blocked by administrator or firewall policy).
pub(crate) const EDE_BLOCKED: u16 = 15;
/// EDE 17: Filtered (The request was filtered by content/security filter, e.g. rebinding).
pub(crate) const EDE_FILTERED: u16 = 17;

/// Builds an RFC 8914 Extended DNS Error [`EdnsOption`].
#[must_use]
pub(crate) fn build_ede_option(info_code: u16, extra_text: Option<&str>) -> EdnsOption {
    let mut bytes = Vec::with_capacity(2 + extra_text.map_or(0, str::len));
    bytes.extend_from_slice(&info_code.to_be_bytes());
    if let Some(text) = extra_text {
        bytes.extend_from_slice(text.as_bytes());
    }
    EdnsOption::Unknown(EDNS_OPTION_CODE_EDE, bytes)
}

/// EXTRA-TEXT attached to every policy block response.
const BLOCKED_BY_POLICY_TEXT: &str = "Antiwire: Blocked by policy";

/// Pre-encoded EDE 15 payload for policy blocks: the info code followed by
/// [`BLOCKED_BY_POLICY_TEXT`]. Encoded once at compile time so the block path
/// only copies it into the option.
static BLOCKED_BY_POLICY_PAYLOAD: [u8; 2 + BLOCKED_BY_POLICY_TEXT.len()] =
    ede_payload(EDE_BLOCKED, BLOCKED_BY_POLICY_TEXT);

/// EDE 15 (Blocked) option for policy block responses.
///
/// Hickory's [`EdnsOption::Unknown`] owns its bytes, so one `Vec` copy of the
/// static payload is the floor; nothing is formatted or re-encoded per call.
#[must_use]
pub(crate) fn blocked_by_policy_option() -> EdnsOption {
    EdnsOption::Unknown(EDNS_OPTION_CODE_EDE, BLOCKED_BY_POLICY_PAYLOAD.to_vec())
}

/// Const encoder for an EDE payload; `N` must equal `2 + text.len()`.
const fn ede_payload<const N: usize>(info_code: u16, text: &str) -> [u8; N] {
    let text = text.as_bytes();
    assert!(N == 2 + text.len(), "EDE payload length mismatch");
    let mut out = [0u8; N];
    let code = info_code.to_be_bytes();
    out[0] = code[0];
    out[1] = code[1];
    let mut i = 0;
    while i < text.len() {
        out[2 + i] = text[i];
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ede_option_wire_encoding_matches_rfc8914() {
        let opt = build_ede_option(EDE_BLOCKED, Some("Antiwire: Blocked"));
        match opt {
            EdnsOption::Unknown(code, data) => {
                assert_eq!(code, 15);
                assert!(data.len() >= 2);
                let info_code = u16::from_be_bytes([data[0], data[1]]);
                assert_eq!(info_code, 15);
                let text = std::str::from_utf8(&data[2..]).expect("valid utf8");
                assert_eq!(text, "Antiwire: Blocked");
            }
            _ => panic!("expected Unknown(15, data)"),
        }
    }

    #[test]
    fn blocked_by_policy_option_matches_dynamic_encoding() {
        assert_eq!(
            blocked_by_policy_option(),
            build_ede_option(EDE_BLOCKED, Some(BLOCKED_BY_POLICY_TEXT))
        );
    }

    #[test]
    fn ede_option_without_extra_text() {
        let opt = build_ede_option(EDE_FILTERED, None);
        match opt {
            EdnsOption::Unknown(code, data) => {
                assert_eq!(code, 15);
                assert_eq!(data.len(), 2);
                let info_code = u16::from_be_bytes([data[0], data[1]]);
                assert_eq!(info_code, 17);
            }
            _ => panic!("expected Unknown(15, data)"),
        }
    }
}
