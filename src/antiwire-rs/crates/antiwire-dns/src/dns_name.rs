//! Zone membership tests on presentation-form domain names.
//!
//! DNS names compare ASCII case-insensitively (RFC 4343). These helpers take
//! names without a trailing dot and never allocate.

/// Whether `name` is `zone` itself or any name below it.
pub(crate) fn is_at_or_below(name: &str, zone: &str) -> bool {
    name.eq_ignore_ascii_case(zone) || dot_before_zone(name, zone).is_some()
}

/// The labels of `name` below `zone`, without the separating dot, or `None`
/// unless `name` is strictly below `zone`.
pub(crate) fn labels_below<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    dot_before_zone(name, zone)
        .map(|dot| &name[..dot])
        .filter(|labels| !labels.is_empty())
}

/// The index of the dot that separates `zone` from the labels above it.
fn dot_before_zone(name: &str, zone: &str) -> Option<usize> {
    let dot = name.len().checked_sub(zone.len() + 1)?;
    // A `.` byte is always a whole character, so both slices below fall on
    // character boundaries.
    (name.as_bytes()[dot] == b'.' && name[dot + 1..].eq_ignore_ascii_case(zone)).then_some(dot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_or_below_requires_a_label_boundary() {
        assert!(is_at_or_below("quad9.net", "quad9.net"));
        assert!(is_at_or_below("dns11.quad9.net", "quad9.net"));
        assert!(is_at_or_below("A.B.NextDNS.io", "nextdns.io"));
        assert!(!is_at_or_below("evilquad9.net", "quad9.net"));
        assert!(!is_at_or_below("quad9.net", "dns.quad9.net"));
        assert!(!is_at_or_below("", "quad9.net"));
    }

    #[test]
    fn multibyte_names_do_not_panic() {
        assert!(!is_at_or_below("testé", "test"));
        assert!(!is_at_or_below("invalidé", "invalid"));
        assert!(!is_at_or_below("é.test", "é.test.x"));
        assert!(is_at_or_below("é.test", "test"));
        assert_eq!(labels_below("é.test", "test"), Some("é"));
    }

    #[test]
    fn labels_below_excludes_the_zone_itself() {
        assert_eq!(
            labels_below("1.0.0.127.in-addr.arpa", "in-addr.arpa"),
            Some("1.0.0.127")
        );
        assert_eq!(labels_below("in-addr.arpa", "in-addr.arpa"), None);
        assert_eq!(labels_below(".in-addr.arpa", "in-addr.arpa"), None);
        assert_eq!(labels_below("xin-addr.arpa", "in-addr.arpa"), None);
    }
}
