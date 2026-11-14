//! Domain name normalization.

use crate::error::{Error, ErrorKind};

/// Maximum length of an ASCII DNS name without a trailing dot.
pub const MAX_DOMAIN_LEN: usize = 253;

const MAX_LABEL_LEN: usize = 63;

/// Normalizes a domain name to lowercase ASCII without trailing dot.
///
/// # Errors
/// Returns an error when the domain is empty or contains invalid characters.
pub fn normalize_domain(domain: &str) -> Result<String, Error> {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return Err(Error::new(ErrorKind::InvalidRule, "empty domain name"));
    }
    let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_dot.is_empty() {
        return Err(Error::new(ErrorKind::InvalidRule, "empty domain name"));
    }
    if without_dot.len() > MAX_DOMAIN_LEN {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!("domain exceeds {MAX_DOMAIN_LEN} bytes"),
        ));
    }
    if !without_dot.is_ascii() || without_dot.parse::<std::net::IpAddr>().is_ok() {
        return Err(Error::new(
            ErrorKind::InvalidRule,
            format!("invalid DNS name {trimmed}"),
        ));
    }
    for label in without_dot.split('.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::new(
                ErrorKind::InvalidRule,
                format!("invalid DNS label in {trimmed}"),
            ));
        }
    }
    Ok(without_dot.to_ascii_lowercase())
}
