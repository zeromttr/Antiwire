//! Platform backend trait.

use firew_core::{AddressSetMode, Error, ErrorKind, Rule, RuleKey};

use crate::config::BackendConfig;
use crate::filter::RuleFilter;
use crate::health::HealthSnapshot;
use crate::native_ref::NativeRuleRef;

/// Enforces a backend's address-set capability against a rule.
///
/// Backends that collapse many remote addresses into one native object report
/// their ceiling from [`Backend::max_address_set_entries`]; backends that emit
/// one native row per address report `None` and reject set-mode rules here so
/// the caller knows to chunk instead. Shared so every backend rejects with the
/// same error kinds and message shape.
///
/// # Errors
///
/// Returns [`ErrorKind::UnsupportedMatcher`] when the backend cannot express a
/// set at all, and [`ErrorKind::LimitExceeded`] when the set is larger than the
/// backend accepts.
pub fn validate_address_set(
    backend: &str,
    rule: &Rule,
    capability: Option<usize>,
) -> Result<(), Error> {
    if rule.address_set_mode() != AddressSetMode::Set {
        return Ok(());
    }
    let Some(limit) = capability else {
        return Err(Error::new(
            ErrorKind::UnsupportedMatcher,
            format!("{backend} cannot represent an address set natively"),
        )
        .with_logical_key(rule.logical_key()));
    };
    let count = rule.remote_addresses().len();
    if count > limit {
        return Err(Error::new(
            ErrorKind::LimitExceeded,
            format!("{backend} accepts {limit} address-set entries; rule holds {count}"),
        )
        .with_logical_key(rule.logical_key()));
    }
    Ok(())
}

/// Error for a rule field `backend` cannot express.
///
/// `platform` is the short backend tag recorded as the error's platform detail.
#[must_use]
pub fn unsupported_matcher(backend: &str, platform: &str, rule: &Rule, field: &str) -> Error {
    Error::new(
        ErrorKind::UnsupportedMatcher,
        format!("{backend} does not support {field}"),
    )
    .with_logical_key(rule.logical_key())
    .with_platform_detail(platform)
}

/// Words in a native tool's error output that mean it lacked privileges.
const PERMISSION_MARKERS: &[&str] = &[
    "operation not permitted",
    "permission denied",
    "you must be root",
    "capability",
    "eperm",
    "eacces",
];

/// Classifies a native command-line tool's error output.
///
/// Missing privileges read the same across `nft`, `iptables`, `ipset`, and
/// `pfctl`. What marks a rejected rule differs per tool, so the caller passes
/// those words as `invalid_markers`. Anything else is [`ErrorKind::Internal`],
/// so a syntax or limit failure is never misreported as a privilege problem.
#[must_use]
pub fn classify_cli_failure(output: &str, invalid_markers: &[&str]) -> ErrorKind {
    let lower = output.to_ascii_lowercase();
    if PERMISSION_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
    {
        ErrorKind::PermissionDenied
    } else if invalid_markers.iter().any(|marker| lower.contains(marker)) {
        ErrorKind::InvalidRule
    } else {
        ErrorKind::Internal
    }
}

/// Whether a native tool's error output says the named object does not exist,
/// as `ipset` and `pfctl` report a missing set or table.
#[must_use]
pub fn reports_missing_object(output: &str) -> bool {
    output.to_ascii_lowercase().contains("does not exist")
}

/// Error for a logical key with no native rule.
#[must_use]
pub fn rule_not_found(key: impl Into<RuleKey>) -> Error {
    Error::new(ErrorKind::RuleNotFound, "rule not found").with_logical_key(key)
}

/// Error for a replacement rule whose key differs from the rule it replaces.
#[must_use]
pub fn key_mismatch(rule: &Rule) -> Error {
    Error::new(
        ErrorKind::InvalidRule,
        "replacement rule key does not match the rule identifier",
    )
    .with_logical_key(rule.logical_key())
}

/// Error for adding a logical key that already has a native rule.
#[must_use]
pub fn duplicate_rule(key: impl Into<RuleKey>) -> Error {
    Error::new(ErrorKind::InvalidRule, "duplicate rule").with_logical_key(key)
}

/// Refuses a rule that still names remote domains. The facade resolves domains
/// into addresses before a rule reaches any backend.
///
/// # Errors
///
/// [`ErrorKind::UnsupportedMatcher`] when `rule` has remote domains.
pub fn reject_unresolved_domains(rule: &Rule) -> Result<(), Error> {
    if rule.remote_domains().is_empty() {
        return Ok(());
    }
    Err(Error::new(
        ErrorKind::UnsupportedMatcher,
        "domain rules are handled by the facade resolver",
    )
    .with_logical_key(rule.logical_key()))
}

/// Checks every native backend runs before its own: the portable rule is
/// valid, an address set fits [`Backend::max_address_set_entries`], and the
/// rule names no remote domains, which no native backend resolves itself.
///
/// `display` is the backend name used in messages, such as `"PF"`.
///
/// # Errors
///
/// The rule's own validation error, an address-set error from
/// [`validate_address_set`], or [`ErrorKind::UnsupportedMatcher`] for remote
/// domains.
pub fn validate_native_rule<B: Backend>(
    backend: &B,
    display: &str,
    rule: &Rule,
) -> Result<(), Error> {
    rule.validate()?;
    validate_address_set(backend.name(), rule, backend.max_address_set_entries())?;
    if !rule.remote_domains().is_empty() {
        return Err(unsupported_matcher(
            display,
            backend.name(),
            rule,
            "remote domains",
        ));
    }
    Ok(())
}

/// Whether the backends built for this target can match on an application path or a
/// package SID. Only the Windows ones can; every other backend refuses such a rule through
/// [`reject_application_matchers`], so a caller can know before it offers one.
pub const APPLICATION_MATCHERS_SUPPORTED: bool = cfg!(windows);

/// Rejects the application path and package SID matchers, which only the
/// Windows backends can express.
///
/// # Errors
///
/// [`ErrorKind::UnsupportedMatcher`] naming the first matcher present.
pub fn reject_application_matchers(
    display: &str,
    platform: &str,
    rule: &Rule,
) -> Result<(), Error> {
    if rule.application_path().is_some() {
        return Err(unsupported_matcher(
            display,
            platform,
            rule,
            "application path",
        ));
    }
    if rule.package_sid().is_some() {
        return Err(unsupported_matcher(display, platform, rule, "package SID"));
    }
    Ok(())
}

/// Native firewall backend contract.
#[allow(clippy::missing_errors_doc)] // platform backends document native failures in `Error`.
pub trait Backend: Send {
    /// Opens the backend with the given configuration.
    fn open(config: &BackendConfig) -> Result<Self, Error>
    where
        Self: Sized;

    /// Backend name for diagnostics.
    fn name(&self) -> &'static str;

    /// Returns whether this backend provides rollback-capable native transactions.
    fn supports_transactions(&self) -> bool;

    /// Maximum remote addresses this backend holds in ONE native object.
    ///
    /// `None` — the default — means the backend emits one native row per
    /// address and cannot represent [`AddressSetMode::Set`]; callers must split
    /// large address lists across several rules. A `Some(n)` backend accepts up
    /// to `n` addresses in a single native set.
    fn max_address_set_entries(&self) -> Option<usize> {
        None
    }

    /// Returns whether this backend supports IPv6 address and protocol matchers.
    fn supports_ipv6(&self) -> bool {
        true
    }

    /// Validates that `rule` can be represented exactly without native mutation.
    fn validate_rule(&self, rule: &Rule) -> Result<(), Error> {
        rule.validate()
    }

    /// Adds a rule to the native firewall.
    fn add_rule(&mut self, rule: &Rule) -> Result<NativeRuleRef, Error>;

    /// Updates an existing native rule and returns its updated native reference.
    fn update_rule(&mut self, id: &NativeRuleRef, rule: &Rule) -> Result<NativeRuleRef, Error>;

    /// Removes a native rule.
    fn remove_rule(&mut self, id: &NativeRuleRef) -> Result<(), Error>;

    /// Fetches a rule by native reference.
    fn get_rule(&self, id: &NativeRuleRef) -> Result<Rule, Error>;

    /// Lists rules matching the filter.
    fn list_rules(&self, filter: &RuleFilter) -> Result<Vec<(NativeRuleRef, Rule)>, Error>;

    /// Begins a native transaction when supported.
    fn begin_transaction(&mut self) -> Result<(), Error>;

    /// Commits a native transaction.
    fn commit_transaction(&mut self) -> Result<(), Error>;

    /// Aborts a native transaction.
    fn abort_transaction(&mut self) -> Result<(), Error>;

    /// Probes native state for managed rules.
    fn health_probe(&self, expected_keys: &[RuleKey]) -> Result<HealthSnapshot, Error>;

    /// Removes all rules owned by this manager namespace.
    fn remove_all_managed(&mut self) -> Result<(), Error>;

    /// Drains rules found under our ownership whose marker no longer parses.
    ///
    /// A rule renamed or edited outside the manager stops being recognisable as
    /// ours. Rather than failing every subsequent operation, backends skip such
    /// rows and report them here so the caller can surface the drift.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot be queried.
    fn take_drift(&mut self) -> Result<Vec<String>, Error> {
        Ok(Vec::new())
    }

    /// Keys that still own managed native rows which do not add up to a rule
    /// [`Backend::list_rules`] reports, such as the surviving half of a
    /// bidirectional rule.
    ///
    /// Those rows can still match traffic. [`Backend::remove_rule`] given a
    /// reference to such a key deletes them, and [`Backend::add_rule`] for the
    /// key replaces them.
    ///
    /// # Errors
    ///
    /// Returns an error when native state cannot be read.
    fn incomplete_keys(&self) -> Result<Vec<RuleKey>, Error> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_address_set;
    use firew_core::{Action, Direction, ErrorKind, Rule};
    use ipnet::IpNet;

    fn nets(count: usize) -> Vec<IpNet> {
        (0..count)
            .map(|index| {
                let octets = u32::try_from(index).expect("index").to_be_bytes();
                IpNet::new(
                    std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect()
    }

    fn set_rule(count: usize) -> Rule {
        Rule::builder("k", Action::Block, Direction::Outbound)
            .remote_address_set(nets(count))
            .build()
            .expect("rule")
    }

    fn cartesian_rule() -> Rule {
        Rule::builder("k", Action::Block, Direction::Outbound)
            .remote_address(nets(1)[0])
            .build()
            .expect("rule")
    }

    #[test]
    fn cartesian_rules_are_always_accepted() {
        let rule = cartesian_rule();
        assert!(validate_address_set("any", &rule, None).is_ok());
        assert!(validate_address_set("any", &rule, Some(1)).is_ok());
    }

    #[test]
    fn backend_without_set_support_rejects_set_rules() {
        let error = validate_address_set("nftables", &set_rule(10), None)
            .expect_err("backend cannot express a set");
        assert_eq!(error.kind(), ErrorKind::UnsupportedMatcher);
    }

    #[test]
    fn set_larger_than_the_backend_ceiling_is_rejected() {
        assert!(validate_address_set("inetfw", &set_rule(100), Some(100)).is_ok());
        let error = validate_address_set("inetfw", &set_rule(101), Some(100))
            .expect_err("over the backend ceiling");
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }
}
