//! The parsed response a reply is encoded from.

use std::sync::Arc;
use std::time::Instant;

use hickory_proto::op::{Edns, Message, Metadata};
use hickory_proto::rr::Record;

use crate::ai::PostResponseWork;
use crate::response_cache::{AgedSections, CachedAnswer, ResponseCache};

/// Parsed response a reply is encoded from.
///
/// A cache hit shares the cached parse tree rather than cloning it: the
/// client-specific header lives in `metadata`, and record sections are copied
/// only when their TTLs must be counted down.
pub(crate) struct PreparedResponse {
    /// Header with the client's transaction ID and RD bit applied.
    pub(crate) metadata: Metadata,
    body: ResponseBody,
    /// Post-response AI work submitted only after the send succeeds.
    /// `None` for malformed, special-use, transport failures, and SERVFAIL.
    post_ai: Option<PostResponseWork>,
    /// A cached answer served past its TTL, which the reply marks EDE 3.
    stale: bool,
}

impl PreparedResponse {
    /// Takes the post-response work, leaving `None` behind.
    pub(crate) fn take_post_ai(&mut self) -> Option<PostResponseWork> {
        self.post_ai.take()
    }

    /// True for a cached answer served past its TTL.
    #[must_use]
    pub(crate) fn stale(&self) -> bool {
        self.stale
    }
}

enum ResponseBody {
    /// Freshly built policy, special-use, error, or miss response.
    Owned(Message),
    /// Cached answer served exactly as stored.
    Shared(Arc<Message>),
    /// Cached answer whose record TTLs have been counted down for this serve.
    Aged {
        shared: Arc<Message>,
        sections: Arc<AgedSections>,
    },
}

impl PreparedResponse {
    #[must_use]
    pub(crate) fn edns(&self) -> Option<&Edns> {
        match &self.body {
            ResponseBody::Owned(message) => message.edns.as_ref(),
            ResponseBody::Shared(shared) | ResponseBody::Aged { shared, .. } => {
                shared.edns.as_ref()
            }
        }
    }

    #[must_use]
    pub(crate) fn answers(&self) -> &[Record] {
        match &self.body {
            ResponseBody::Owned(message) => &message.answers,
            ResponseBody::Shared(shared) => &shared.answers,
            ResponseBody::Aged { sections, .. } => &sections.answers,
        }
    }

    #[must_use]
    pub(crate) fn authorities(&self) -> &[Record] {
        match &self.body {
            ResponseBody::Owned(message) => &message.authorities,
            ResponseBody::Shared(shared) => &shared.authorities,
            ResponseBody::Aged { sections, .. } => &sections.authorities,
        }
    }

    #[must_use]
    pub(crate) fn additionals(&self) -> &[Record] {
        match &self.body {
            ResponseBody::Owned(message) => &message.additionals,
            ResponseBody::Shared(shared) => &shared.additionals,
            ResponseBody::Aged { sections, .. } => &sections.additionals,
        }
    }
}

/// Serves a cached answer by sharing its parse tree with the encoder.
///
/// Only the header is copied (it is `Copy`); records are cloned solely when
/// [`ResponseCache::age_sections`] must count their TTLs down.
pub(super) fn prepare_cached_message(
    cached: CachedAnswer,
    request: &Message,
    post_ai: Option<PostResponseWork>,
) -> PreparedResponse {
    let mut metadata = cached.parsed_message.metadata;
    metadata.id = request.metadata.id;
    metadata.recursion_desired = request.metadata.recursion_desired;
    // RFC 6840 §5.8: AD goes only to a client that asked, by AD or DO.
    metadata.authentic_data &= request.metadata.authentic_data
        || request
            .edns
            .as_ref()
            .is_some_and(|edns| edns.flags().dnssec_ok);
    let stale = Instant::now() >= cached.fresh_until;
    let body = match ResponseCache::age_sections(&cached) {
        Some(sections) => ResponseBody::Aged {
            shared: cached.parsed_message,
            sections,
        },
        None => ResponseBody::Shared(cached.parsed_message),
    };
    PreparedResponse {
        metadata,
        body,
        post_ai,
        stale,
    }
}

pub(crate) fn prepare_uncached_message(
    message: Message,
    post_ai: Option<PostResponseWork>,
) -> PreparedResponse {
    PreparedResponse {
        metadata: message.metadata,
        body: ResponseBody::Owned(message),
        post_ai,
        stale: false,
    }
}
