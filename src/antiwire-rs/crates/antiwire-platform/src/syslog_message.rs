//! Syslog message formats and their framing for the SIEM syslog sink.
//!
//! Plain UDP and TCP carry RFC 3164 messages, the format the Wazuh manager's
//! pre-decoder reads; it does not parse RFC 5424 (wazuh/wazuh#16994). TLS
//! carries RFC 5424, which RFC 5425 requires, so a TLS collector such as
//! rsyslog or syslog-ng gets the structured header.

use std::net::IpAddr;

use time::{OffsetDateTime, UtcOffset};

/// Facility local0 (16) and severity informational (6): `16 * 8 + 6`.
const PRIORITY: u8 = 134;
const APP_NAME: &str = "antiwire";
/// RFC 5424 §6.2.4: HOSTNAME is at most 255 octets.
const MAX_HOSTNAME: usize = 255;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// RFC 3164 §4.1: `<PRI>Mmm dd hh:mm:ss HOSTNAME TAG[PID]: MSG`.
///
/// The day is padded with a space, not a zero (§4.1.2), and the time is the
/// sender's local time, which the caller supplies.
pub(crate) fn rfc3164(now: OffsetDateTime, hostname: &str, pid: u32, message: &str) -> String {
    format!(
        "<{PRIORITY}>{} {:>2} {:02}:{:02}:{:02} {} {APP_NAME}[{pid}]: {message}",
        MONTHS[usize::from(u8::from(now.month())) - 1],
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        rfc3164_hostname(hostname),
    )
}

/// RFC 5424 §6: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG`.
///
/// The timestamp is UTC with microseconds, the most TIME-SECFRAC allows
/// (§6.2.3). MSGID and STRUCTURED-DATA are the NILVALUE `-`. The JSON body is
/// sent without a BOM, which makes it MSG-ANY rather than MSG-UTF8 (§6.4).
pub(crate) fn rfc5424(now: OffsetDateTime, hostname: &str, pid: u32, message: &str) -> String {
    let now = now.to_offset(UtcOffset::UTC);
    format!(
        "<{PRIORITY}>1 {:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z {} {APP_NAME} {pid} - - {message}",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second(),
        now.microsecond(),
        rfc5424_hostname(hostname),
    )
}

/// RFC 6587 §3.4.2 non-transparent framing, for plain TCP: each message ends
/// with LF. The JSON body never holds a raw LF, since `serde_json` escapes
/// control characters, and the header fields are printable ASCII.
pub(crate) fn lf_framed(message: &str) -> Vec<u8> {
    let mut frame = Vec::with_capacity(message.len() + 1);
    frame.extend_from_slice(message.as_bytes());
    frame.push(b'\n');
    frame
}

/// RFC 5425 §4.3 octet counting, which TLS transport requires:
/// `MSG-LEN SP SYSLOG-MSG`, the length in octets.
pub(crate) fn octet_counted(message: &str) -> Vec<u8> {
    let mut frame = format!("{} ", message.len()).into_bytes();
    frame.extend_from_slice(message.as_bytes());
    frame
}

/// Printable US-ASCII only (RFC 5424 PRINTUSASCII, %d33-126): no spaces,
/// which would shift every later header field.
fn printable(hostname: &str) -> String {
    hostname
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_HOSTNAME)
        .collect()
}

/// RFC 3164 §4.1.2: the host name without its domain, or an IP address.
fn rfc3164_hostname(hostname: &str) -> String {
    let hostname = printable(hostname);
    let short = if hostname.parse::<IpAddr>().is_ok() {
        hostname.as_str()
    } else {
        hostname.split('.').next().unwrap_or_default()
    };
    if short.is_empty() {
        "localhost".to_owned()
    } else {
        short.to_owned()
    }
}

/// RFC 5424 §6.2.4: the NILVALUE when the host name is unknown.
fn rfc5424_hostname(hostname: &str) -> String {
    let hostname = printable(hostname);
    if hostname.is_empty() {
        "-".to_owned()
    } else {
        hostname
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn rfc3164_pads_the_day_with_a_space_and_drops_the_domain() {
        let line = rfc3164(
            datetime!(2026-10-01 09:05:07 UTC),
            "workstation.corp.example",
            42,
            "{\"a\":1}",
        );
        assert_eq!(
            line,
            "<134>Oct  1 09:05:07 workstation antiwire[42]: {\"a\":1}"
        );
    }

    #[test]
    fn rfc3164_keeps_an_address_and_fills_a_missing_name() {
        let now = datetime!(2026-12-25 23:59:59 UTC);
        assert!(rfc3164(now, "192.0.2.10", 1, "m").contains(" 192.0.2.10 antiwire[1]:"));
        assert!(rfc3164(now, "  ", 1, "m").contains(" localhost antiwire[1]:"));
    }

    #[test]
    fn rfc5424_has_a_version_utc_microseconds_and_nil_fields() {
        let line = rfc5424(
            datetime!(2026-10-21 14:30:00.123456789 +02:00),
            "work station",
            7,
            "{}",
        );
        assert_eq!(
            line,
            "<134>1 2026-10-21T12:30:00.123456Z workstation antiwire 7 - - {}"
        );
        assert!(rfc5424(datetime!(2026-01-01 0:00 UTC), "", 7, "{}").contains("Z - antiwire 7"));
    }

    #[test]
    fn framing_follows_rfc_6587_and_rfc_5425() {
        assert_eq!(lf_framed("<134>x"), b"<134>x\n");
        // "é" is two octets, so the count is in octets, not characters.
        assert_eq!(octet_counted("<134>é"), "7 <134>é".as_bytes());
    }
}
