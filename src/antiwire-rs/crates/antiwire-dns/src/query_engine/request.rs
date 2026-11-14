//! The engine's view of an incoming query: validation, and the parsed state a
//! miss carries so it never re-parses or re-evaluates policy.

use hickory_proto::op::{Edns, Message, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_server::zone_handler::MessageRequest;

use crate::domain_key::{self, DomainKey};
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

pub(super) struct QuestionParts {
    pub(super) normalized: DomainKey,
    pub(super) qtype: RecordType,
    pub(super) qclass: u16,
}

/// Common semantic view over hickory's server request and the crate's public
/// `Message` API. The server implementation reads Hickory's existing parse
/// tree; converting to an owned `Message` is deferred until a miss, policy
/// block, or error response actually needs one. Special-use answers clone
/// only the matching question via [`RequestView::first_query`].
pub(super) trait RequestView {
    fn metadata(&self) -> &Metadata;
    fn query_count(&self) -> usize;
    fn question(&self) -> Option<QuestionParts>;
    fn edns(&self) -> Option<&Edns>;
    fn to_message(&self) -> Message;
    /// First question, cloned only when a response must echo it.
    fn first_query(&self) -> Option<Query>;
}

impl RequestView for Message {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn query_count(&self) -> usize {
        self.queries.len()
    }

    fn question(&self) -> Option<QuestionParts> {
        let query = self.queries.first()?;
        Some(QuestionParts {
            normalized: domain_key::from_name(query.name(), true),
            qtype: query.query_type(),
            qclass: u16::from(query.query_class()),
        })
    }

    fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    fn to_message(&self) -> Message {
        self.clone()
    }

    fn first_query(&self) -> Option<Query> {
        self.queries.first().cloned()
    }
}

impl RequestView for MessageRequest {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn query_count(&self) -> usize {
        self.queries.len()
    }

    fn question(&self) -> Option<QuestionParts> {
        let query = self.queries.queries().first()?;
        Some(QuestionParts {
            // `LowerQuery` already owns Hickory's lowercase form.
            normalized: domain_key::from_name(query.name(), false),
            qtype: query.query_type(),
            qclass: u16::from(query.query_class()),
        })
    }

    fn edns(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }

    fn to_message(&self) -> Message {
        let mut message = Message::new(
            self.metadata.id,
            self.metadata.message_type,
            self.metadata.op_code,
        );
        message.metadata = self.metadata;
        message.queries = self
            .queries
            .queries()
            .iter()
            .map(|query| query.original().clone())
            .collect();
        message.answers.clone_from(&self.answers);
        message.authorities.clone_from(&self.authorities);
        message.additionals.clone_from(&self.additionals);
        message.signature.clone_from(&self.signature);
        message.edns.clone_from(&self.edns);
        message
    }

    fn first_query(&self) -> Option<Query> {
        self.queries
            .queries()
            .first()
            .map(|query| query.original().clone())
    }
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
pub(super) fn validate_request<R: RequestView>(request: &R) -> Option<ResponseCode> {
    if request.metadata().op_code != OpCode::Query {
        return Some(ResponseCode::NotImp);
    }
    if request.edns().is_some_and(|edns| edns.version() > 0) {
        return Some(ResponseCode::BADVERS);
    }
    if request.query_count() != 1 {
        return Some(ResponseCode::FormErr);
    }
    None
}

pub(super) fn parse_query<R: RequestView>(request: &R) -> Result<PreparedQuery> {
    let question = request
        .question()
        .ok_or_else(|| DnsError::InvalidQuery("missing query".to_owned()))?;
    let flags = QueryFlags {
        recursion_desired: request.metadata().recursion_desired,
        edns: request.edns().is_some(),
        dnssec_ok: request.edns().is_some_and(|edns| edns.flags().dnssec_ok),
        checking_disabled: request.metadata().checking_disabled,
    };
    let cache_eligible = request.edns().is_none_or(cache_safe_edns);
    let cache_key =
        CacheKey::from_normalized_query(question.normalized, question.qtype, question.qclass)
            .with_flags(flags);
    Ok(PreparedQuery {
        qtype: question.qtype,
        cache_key,
        cache_eligible,
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
