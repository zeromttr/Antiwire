//! Classification of Hickory transport failures for tier health and logs.

use hickory_proto::op::Message;
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError};

use crate::messages::build_error_response;

/// Whether the error came from a DNS response rather than the transport.
///
/// A refused or failed *answer* still travelled to a server and back, so the
/// tier is reachable; only transport errors count against it. A truncated
/// answer is one too: Hickory reports it when the server set TC and the retry
/// over TCP was truncated as well, or the server has no TCP to retry on.
pub(super) fn is_dns_level_error(error: &NetError) -> bool {
    matches!(error, NetError::Dns(_) | NetError::Truncated)
}

/// Short machine-facing label for one failure. The full error, including any
/// HTTP/2 `ENHANCE_YOUR_CALM` guard detail, is logged alongside it.
pub(super) fn upstream_error_kind(error: &NetError) -> &'static str {
    if error.is_connection_closed() {
        return "connection_closed";
    }
    match error {
        NetError::Timeout => "timeout",
        NetError::Io(io) if io.kind() == std::io::ErrorKind::TimedOut => "timeout",
        NetError::Io(_) => "io",
        NetError::Dns(_) => "dns",
        NetError::Truncated => "truncated",
        NetError::Busy => "busy",
        NetError::NoConnections => "no_connections",
        NetError::H2(_) => "http2",
        NetError::H3(_) => "http3",
        NetError::QuinnConnect(_) | NetError::QuinnConnection(_) => "quic",
        NetError::RustlsError(_) => "tls",
        _ => "other",
    }
}

/// Hickory reports empty-but-valid DNS outcomes as errors; treat them as successful answers.
pub(super) fn is_benign_empty_answer(error: &NetError) -> bool {
    matches!(
        error,
        NetError::Dns(HickoryDnsError::NoRecordsFound(no_records))
            if matches!(
                no_records.response_code,
                hickory_proto::op::ResponseCode::NoError
                    | hickory_proto::op::ResponseCode::NXDomain
            )
    )
}

/// Rebuilds the negative answer hickory reported as an error.
///
/// `NoRecords` carries the authority section it parsed off the wire — the SOA and
/// any NS referral records. Dropping them would leave a response with no records
/// at all, which costs both the client its own negative-caching input and
/// [`crate::response_cache::ResponseCache`] the RFC 2308 TTL it derives from the SOA. Everything
/// hickory kept is put back.
pub(super) fn empty_answer_for_error(request: &Message, error: &NetError) -> Message {
    let no_records = match error {
        NetError::Dns(HickoryDnsError::NoRecordsFound(no_records)) => Some(no_records),
        _ => None,
    };

    let rcode = no_records.map_or_else(
        || {
            if error.is_nx_domain() {
                hickory_proto::op::ResponseCode::NXDomain
            } else {
                hickory_proto::op::ResponseCode::NoError
            }
        },
        |no_records| no_records.response_code,
    );

    let mut response = build_error_response(request, rcode);
    let Some(no_records) = no_records else {
        return response;
    };

    // `authorities` is the full section when present; `soa` is the single record
    // hickory extracted from it. Prefer the section so NS referrals survive, and
    // fall back to the SOA alone so the negative TTL is never lost.
    if let Some(authorities) = no_records.authorities.as_ref() {
        for record in authorities.iter() {
            response.add_authority(record.clone());
        }
    } else if let Some(soa) = no_records.soa.as_ref() {
        response.add_authority(soa.as_ref().clone().into_record_of_rdata());
    }

    response
}
