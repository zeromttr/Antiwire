//! The engine's view of an incoming query: validation, and the parsed state a
//! miss carries so it never re-parses or re-evaluates policy.

use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::rr::RecordType;

use crate::domain_key;
use crate::response_cache::{CacheKey, QueryFlags};
use crate::{DnsError, Result};

/// Parsed query state carried from the synchronous fast path into the miss path,
/// so the miss path never re-parses or re-evaluates policy.
#[derive(Debug)]
pub(crate) struct PreparedQuery {
    pub(super) qtype: RecordType,
    pub(super) cache_key: CacheKey,
    /// Options whose response semantics are not represented by the cache key
    /// bypass caching. Options never forwarded upstream (see
    /// `upstream::forwards_edns_option`) do not make an otherwise standard
    /// query miss.
    pub(super) cache_eligible: bool,
    /// Explicit user allow rule matched: automatic AI blocking must not
    /// override it. Retained so AI integration never discards an allow.
    pub(super) explicit_allow: bool,
}

/// Rejects queries that are not single-question standard queries: FORMERR for
/// multi-question messages, NOTIMP for unsupported opcodes. Without this,
/// questions beyond the first would be forwarded upstream unevaluated by
/// policy and cached under the first question's key. Responses never get
/// here: the listeners drop them before parsing.
///
/// An EDNS version above 0, the only one this resolver speaks, gets BADVERS
/// (RFC 6891 §6.1.3). The reply's OPT is version 0, which tells the client
/// what to retry with.
pub(super) fn validate_request(request: &Message) -> Option<ResponseCode> {
    if request.metadata.op_code != OpCode::Query {
        return Some(ResponseCode::NotImp);
    }
    if request.edns.as_ref().is_some_and(|edns| edns.version() > 0) {
        return Some(ResponseCode::BADVERS);
    }
    if request.queries.len() != 1 {
        return Some(ResponseCode::FormErr);
    }
    None
}

pub(super) fn parse_query(request: &Message) -> Result<PreparedQuery> {
    let question = request
        .queries
        .first()
        .ok_or_else(|| DnsError::InvalidQuery("missing query".to_owned()))?;
    let qtype = question.query_type();
    let cache_key = CacheKey::from_normalized_query(
        domain_key::from_name(question.name()),
        qtype,
        u16::from(question.query_class()),
    )
    .with_flags(QueryFlags::from_request(request));
    Ok(PreparedQuery {
        qtype,
        cache_key,
        cache_eligible: request.edns.as_ref().is_none_or(cache_safe_edns),
        explicit_allow: false,
    })
}

/// Returns whether an EDNS request can be reconstructed exactly from the
/// compact cache key. Payload size is deliberately excluded: it affects
/// transport truncation, not the upstream answer semantics.
fn cache_safe_edns(edns: &Edns) -> bool {
    edns.version() == 0
        && edns.rcode_high() == 0
        && edns.flags().z == 0
        && edns
            .options()
            .as_ref()
            .iter()
            .all(|(code, _)| !crate::upstream::forwards_edns_option(*code))
}
