//! Cache lookup keys and the query bits that make an answer valid.

#[cfg(any(test, feature = "bench-internals"))]
use hickory_proto::op::Message;

use crate::domain_key::DomainKey;

/// Query properties that change what a correct answer looks like, and so
/// must not be shared between cache entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the four flags are independent DNS protocol bits, not application state"
)]
pub(crate) struct QueryFlags {
    /// RD header bit: authoritative/non-recursive answers must not alias the
    /// recursive answer normally requested by stub clients.
    pub(crate) recursion_desired: bool,
    /// Client sent an OPT record. A non-EDNS client must not receive one back.
    pub(crate) edns: bool,
    /// EDNS DO bit: DNSSEC answers carry RRSIGs that plain queries must not get.
    pub(crate) dnssec_ok: bool,
    /// CD header bit: checking-disabled answers bypass upstream validation.
    pub(crate) checking_disabled: bool,
}

impl QueryFlags {
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub(crate) fn from_request(request: &Message) -> Self {
        let edns = request.edns.as_ref();
        Self {
            recursion_desired: request.metadata.recursion_desired,
            edns: edns.is_some(),
            dnssec_ok: edns.is_some_and(|edns| edns.flags().dnssec_ok),
            checking_disabled: request.metadata.checking_disabled,
        }
    }
}

/// Cache lookup key for a DNS question.
///
/// The domain is stored inline (see [`DomainKey`]), so building, hashing, and
/// cloning a key never touches the heap for any valid unescaped name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CacheKey {
    pub(crate) domain: DomainKey,
    pub(crate) qtype: hickory_proto::rr::RecordType,
    pub(crate) qclass: u16,
    pub(crate) flags: QueryFlags,
}

impl CacheKey {
    #[cfg(any(test, feature = "bench-internals"))]
    #[must_use]
    pub(crate) fn from_query(
        domain: &str,
        qtype: hickory_proto::rr::RecordType,
        qclass: u16,
    ) -> Self {
        Self {
            domain: crate::domain_key::from_presentation(domain.to_owned()),
            qtype,
            qclass,
            flags: QueryFlags::default(),
        }
    }

    /// Builds a key from a domain that has already been normalized.
    pub(crate) fn from_normalized_query(
        domain: DomainKey,
        qtype: hickory_proto::rr::RecordType,
        qclass: u16,
    ) -> Self {
        debug_assert!(!domain.bytes().any(|byte| byte.is_ascii_uppercase()));
        Self {
            domain,
            qtype,
            qclass,
            flags: QueryFlags::default(),
        }
    }

    #[must_use]
    pub(crate) fn with_flags(mut self, flags: QueryFlags) -> Self {
        self.flags = flags;
        self
    }
}
