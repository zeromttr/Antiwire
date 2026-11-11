//! Evidence strength carried by a persisted `dst_domain`.
//!
//! A stored domain encodes how it was attributed: an empty value or a bare IP
//! placeholder is no evidence at all, a name resolved from shared DNS state is
//! retained for display with the [`INFERRED_SUFFIX`], and any other name was
//! confirmed for the owning process. The same preference has to be applied by
//! the enrichment path, the active-flow persistence mirror, and the SQLite
//! update, so the classification lives here instead of in each caller.

/// Suffix appended to a persisted inferred domain for display.
pub const INFERRED_SUFFIX: &str = " (inferred)";

/// The strongest scope a stored domain can represent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainEvidence {
    /// No domain: empty, or a bare IP placeholder.
    None,
    /// A name inferred from shared/global DNS evidence.
    Inferred,
    /// A name confirmed for the owning process.
    Confirmed,
}

/// Returns true when `domain` is a displayed inferred domain.
#[must_use]
pub fn domain_is_inferred(domain: &str) -> bool {
    domain.trim_end().ends_with(INFERRED_SUFFIX)
}

/// Classifies a persisted domain by the strength of the evidence behind it.
#[must_use]
pub fn domain_evidence(domain: &str) -> DomainEvidence {
    let trimmed = domain.trim();
    if trimmed.is_empty() || looks_like_ip(trimmed) {
        DomainEvidence::None
    } else if domain_is_inferred(trimmed) {
        DomainEvidence::Inferred
    } else {
        DomainEvidence::Confirmed
    }
}

/// Chooses the domain to keep when a stored value meets a newer observation.
///
/// `None` yields to either stronger tier, an inferred name yields only to a
/// confirmed one, and a confirmed name is never replaced. A same-tier
/// observation keeps the stored value so repeated enrichment does not rewrite
/// the row. The `(inferred)` suffix is preserved on the chosen value.
///
/// A writer that judged the name again from better evidence says so, with
/// [`NewConnectionLog::replace_domain`](crate::NewConnectionLog::replace_domain),
/// and its domain is then stored without asking this.
#[must_use]
pub fn prefer_dst_domain(existing: &str, new: &str) -> String {
    match (domain_evidence(existing), domain_evidence(new)) {
        (_, DomainEvidence::None) => existing.to_owned(),
        (DomainEvidence::None, _) | (DomainEvidence::Inferred, DomainEvidence::Confirmed) => {
            new.to_owned()
        }
        (DomainEvidence::Confirmed, _) | (DomainEvidence::Inferred, DomainEvidence::Inferred) => {
            existing.to_owned()
        }
    }
}

fn looks_like_ip(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_each_tier() {
        assert_eq!(domain_evidence(""), DomainEvidence::None);
        assert_eq!(domain_evidence("  "), DomainEvidence::None);
        assert_eq!(domain_evidence("203.0.113.5"), DomainEvidence::None);
        assert_eq!(domain_evidence("2001:db8::1"), DomainEvidence::None);
        assert_eq!(
            domain_evidence("example.com (inferred)"),
            DomainEvidence::Inferred
        );
        assert_eq!(domain_evidence("example.com"), DomainEvidence::Confirmed);
    }

    #[test]
    fn inferred_yields_to_confirmed() {
        assert_eq!(
            prefer_dst_domain("example.com (inferred)", "example.com"),
            "example.com"
        );
        assert_eq!(
            prefer_dst_domain("a.example (inferred)", "b.example"),
            "b.example"
        );
    }

    #[test]
    fn confirmed_is_stable_and_none_backfills() {
        assert_eq!(
            prefer_dst_domain("a.example", "b.example"),
            "a.example",
            "a confirmed name must survive a competing observation"
        );
        assert_eq!(
            prefer_dst_domain("203.0.113.5", "b.example"),
            "b.example",
            "a resolved name replaces an IP placeholder"
        );
        assert_eq!(
            prefer_dst_domain("", "example.com (inferred)"),
            "example.com (inferred)"
        );
    }

    #[test]
    fn same_tier_keeps_the_stored_value() {
        assert_eq!(
            prefer_dst_domain("a.example (inferred)", "b.example (inferred)"),
            "a.example (inferred)",
            "inferred evidence never replaces inferred evidence"
        );
        assert_eq!(prefer_dst_domain("a.example", ""), "a.example");
    }
}
