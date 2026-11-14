//! Hostname normalization for registry queries.

use crate::error::Error;

/// Names to ask the registry, from the full hostname down to the registered name.
///
/// The last entry still has two labels. A single-label TLD is not a registration.
/// Parent names are tried only after the registry says the longer name is absent,
/// so this does not need a third-party suffix list.
pub(crate) fn query_names(domain: &str) -> Result<Vec<String>, Error> {
    let domain = normalize(domain)?;
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|label| !valid_label(label)) || is_ipv4(&labels) {
        return Err(Error::InvalidDomain);
    }
    if domain.len() > 253 {
        return Err(Error::InvalidDomain);
    }
    Ok((0..labels.len() - 1)
        .map(|start| labels[start..].join("."))
        .collect())
}

/// Lowercase ASCII, with an internationalised name converted to its A-labels.
///
/// The IANA bootstrap lists TLDs as A-labels and registries index A-labels
/// (RFC 9224 §4, RFC 5891), so `пример.рф` is asked as
/// `xn--e1afmkfd.xn--p1ai` rather than rejected.
fn normalize(domain: &str) -> Result<String, Error> {
    let domain = domain.trim().trim_end_matches('.');
    if domain.is_empty() || domain.contains(['/', '\\', ':', '@', ' ', '\t']) {
        return Err(Error::InvalidDomain);
    }
    if domain.is_ascii() {
        return Ok(domain.to_ascii_lowercase());
    }
    match url::Host::parse(domain) {
        Ok(url::Host::Domain(ascii)) => Ok(ascii),
        _ => Err(Error::InvalidDomain),
    }
}

fn is_ipv4(labels: &[&str]) -> bool {
    labels.len() == 4
        && labels
            .iter()
            .all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
}

fn valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
        return false;
    };
    (1..=63).contains(&bytes.len())
        && first.is_ascii_alphanumeric()
        && last.is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_from_the_full_name_down_to_two_labels() {
        assert_eq!(
            query_names("WWW.Example.COM.").unwrap(),
            ["www.example.com", "example.com"]
        );
        assert_eq!(
            query_names("a.b.example.co.uk").unwrap(),
            [
                "a.b.example.co.uk",
                "b.example.co.uk",
                "example.co.uk",
                "co.uk"
            ]
        );
    }

    #[test]
    fn rejects_a_bare_tld_scheme_or_empty_label() {
        assert!(query_names("com").is_err());
        assert!(query_names("https://example.com").is_err());
        assert!(query_names("example..com").is_err());
        assert!(query_names("").is_err());
        assert!(query_names("-bad.example").is_err());
        assert!(query_names("192.0.2.1").is_err());
    }

    #[test]
    fn converts_an_internationalised_name_to_a_labels() {
        assert_eq!(
            query_names("WWW.Пример.РФ.").unwrap(),
            ["www.xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"]
        );
        assert_eq!(query_names("münchen.de").unwrap(), ["xn--mnchen-3ya.de"]);
        // Already-encoded names pass through unchanged.
        assert_eq!(
            query_names("xn--mnchen-3ya.de").unwrap(),
            ["xn--mnchen-3ya.de"]
        );
        assert!(query_names("bad\u{0}name.de").is_err());
    }
}
