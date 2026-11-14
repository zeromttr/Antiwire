use std::net::IpAddr;

use ipnet::IpNet;

use crate::hash::reverse_hash_pair;
use crate::normalize::with_normalized_domain;
use crate::rule::Verdict;
use crate::rule_index::IpRuleEntry;

use super::dns_index::decide_normalized_domain;
use super::domain::{DomainDecision, PolicyEngine};
use super::RuleEngine;

impl RuleEngine {
    /// Domain-only hot path for DNS resolver and ETW observers.
    #[must_use]
    pub fn evaluate_domain(&self, domain: &str) -> Option<Verdict> {
        self.evaluate_domain_with_source(domain)
            .map(|decision| decision.verdict)
    }

    /// Single-pass domain evaluation returning the verdict and block source together.
    #[must_use]
    pub fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        with_normalized_domain(domain, |domain| {
            self.evaluate_normalized_domain_with_source(domain)
        })
    }

    /// Domain evaluation for callers that guarantee `domain` is already
    /// lowercase ASCII (e.g. DNS-normalized names), skipping re-normalization.
    #[must_use]
    pub fn evaluate_normalized_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        decide_normalized_domain(
            &self.dns_rules,
            &self.dns_wildcards,
            domain,
            |domain| self.blocklist_boot_gate.blocks_normalized(domain),
            |domain| self.blocklist.is_normalized_domain_blocked(domain),
        )
    }

    /// Full connection evaluation without side effects.
    ///
    /// # Examples
    ///
    /// ```
    /// use antiwire_policy::{RuleEngine, Verdict};
    ///
    /// let engine = RuleEngine::new();
    /// assert_eq!(engine.evaluate(r"C:\app.exe", "1.2.3.4", "example.com"), None);
    /// let _ = Verdict::Allow;
    /// ```
    #[must_use]
    pub fn evaluate(&self, app_path: &str, dest_ip: &str, dest_domain: &str) -> Option<Verdict> {
        self.evaluate_internal(app_path, dest_ip, dest_domain)
    }

    /// Full connection evaluation when the caller already has a parsed address.
    #[must_use]
    pub fn evaluate_with_ip(
        &self,
        app_path: &str,
        dest_ip: IpAddr,
        dest_domain: &str,
    ) -> Option<Verdict> {
        self.evaluate_internal_with_ip(app_path, Some(dest_ip), dest_domain)
    }
    /// Named blocklists that currently match `domain` or one of its suffixes.
    ///
    /// Empty when the domain is not on a named list, including untagged test
    /// snapshots and the fail-closed boot window.
    #[must_use]
    pub fn matching_blocklists(&self, domain: &str) -> Vec<String> {
        with_normalized_domain(domain, |domain| {
            Some(self.blocklist.matching_normalized_blocklists(domain))
        })
        .unwrap_or_default()
    }

    /// Named blocklists matching an already-normalized domain.
    #[must_use]
    pub fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        self.blocklist.matching_normalized_blocklists(domain)
    }

    fn evaluate_internal(
        &self,
        app_path: &str,
        dest_ip: &str,
        dest_domain: &str,
    ) -> Option<Verdict> {
        let dest_ip = dest_ip.parse::<IpAddr>().ok();
        self.evaluate_internal_with_ip(app_path, dest_ip, dest_domain)
    }

    /// The verdict for one connection.
    ///
    /// An application rule decides first, then a domain rule. A block on the
    /// destination address or its country still overrides an allow from
    /// either: the host firewall enforces address and country blocks over any
    /// allow, so a verdict of Allow there would not be what actually happened.
    fn evaluate_internal_with_ip(
        &self,
        app_path: &str,
        dest_ip: Option<IpAddr>,
        dest_domain: &str,
    ) -> Option<Verdict> {
        let named = self.app_or_domain_verdict(app_path, dest_domain);
        if named == Some(Verdict::Block) {
            return named;
        }
        let address = dest_ip.and_then(|address| {
            let prefix_len = if address.is_ipv4() { 32 } else { 128 };
            let network = IpNet::new(address, prefix_len)
                .expect("a host-length prefix is valid for every IP address");
            self.lookup_ip_rule(&network).map(|entry| entry.verdict)
        });
        match address {
            Some(Verdict::Block) => address,
            _ => named.or(address),
        }
    }

    fn app_or_domain_verdict(&self, app_path: &str, dest_domain: &str) -> Option<Verdict> {
        if !app_path.is_empty() {
            // The exact identity wins first, so a per-service / per-module
            // rule overrides a rule on the whole host below. A rundll32 module
            // label is read from the process's own command line, which the
            // module can rewrite, so an allow on one is not trusted.
            if let Some(verdict) = self
                .lookup_app_verdict(app_path)
                .filter(|verdict| *verdict == Verdict::Block || !is_self_reported_label(app_path))
            {
                return Some(verdict);
            }
            // A rule created for an earlier install version keeps covering the
            // current path after an in-place update.
            if let Some(verdict) = self.lookup_normalized_app_verdict(app_path) {
                return Some(verdict);
            }
            // Disambiguated host identities also honor a rule on the bare host
            // executable, so a rule created for the whole host keeps covering
            // every disambiguated row.
            if let Some(host) = host_exe_prefix(app_path) {
                if let Some(verdict) = self.lookup_app_verdict(host) {
                    return Some(verdict);
                }
                if let Some(verdict) = self.lookup_normalized_app_verdict(host) {
                    return Some(verdict);
                }
            }
        }

        self.evaluate_domain_with_source(dest_domain)
            .map(|decision| decision.verdict)
    }

    /// Exact app-rule lookup: the most-recently-added matching rule wins.
    fn lookup_app_verdict(&self, app_path: &str) -> Option<Verdict> {
        self.app_rules
            .get(&reverse_hash_pair(app_path))
            .and_then(|rules| {
                rules
                    .iter()
                    .rev()
                    .find(|rule| rule.target.eq_ignore_ascii_case(app_path))
            })
            .map(|rule| rule.verdict)
    }

    /// Version-family app-rule lookup, tried only when no exact rule matched.
    ///
    /// Every rule in a bucket shares the normalized key, so the
    /// most-recently-added rule decides, matching the exact lookup's semantics.
    /// Only a block is inherited this way. A path in the same install root does
    /// not prove the executable is the same application, because those
    /// directories are often user-writable; an allow reaches a new version only
    /// when the rule service moves it there after checking the publisher.
    /// The empty check keeps the per-flow path allocation-free when the user
    /// has no application rules at all.
    fn lookup_normalized_app_verdict(&self, app_path: &str) -> Option<Verdict> {
        if self.app_rules_normalized.is_empty() {
            return None;
        }
        self.app_rules_normalized
            .get(&crate::app_rule_identity(app_path))
            .and_then(|rules| rules.last())
            .map(|rule| rule.verdict)
            .filter(|verdict| *verdict == Verdict::Block)
    }

    fn lookup_ip_rule(&self, network: &IpNet) -> Option<IpRuleEntry> {
        let user = self
            .ip_rules
            .get_lpm(network)
            .and_then(|(prefix, entries)| {
                entries.last().map(|entry| (prefix.prefix_len(), *entry))
            });
        let country = self
            .country_ip_rules
            .get_lpm(network)
            .and_then(|(prefix, entries)| {
                entries.last().map(|entry| (prefix.prefix_len(), *entry))
            });

        match (user, country) {
            (Some((user_len, user)), Some((country_len, country))) => {
                Some(if user_len >= country_len {
                    user
                } else {
                    country
                })
            }
            (Some((_, user)), None) => Some(user),
            (None, Some((_, country))) => Some(country),
            (None, None) => None,
        }
    }
}

/// Whether `app_path` is a rundll32 module identity. Unlike a svchost service
/// name, which comes from the Service Control Manager, the module is whatever
/// the process's command line says.
fn is_self_reported_label(app_path: &str) -> bool {
    host_exe_prefix(app_path).is_some_and(|host| {
        host.rsplit(['\\', '/'])
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case("rundll32.exe"))
    })
}

/// Returns the host executable prefix of a disambiguated application identity.
///
/// The svchost and rundll32 resolvers share one `exe::label` shape
/// (`C:\Windows\System32\svchost.exe::Dnscache`), so one function covers both:
/// the prefix is the icon source and the whole-host rule target. Returns
/// `None` when the path carries no `::label` suffix. A real Windows path can
/// never contain `::`, so the suffix always marks a synthetic identity.
pub(super) fn host_exe_prefix(app_path: &str) -> Option<&str> {
    let (prefix, _) = app_path.split_once("::")?;
    (!prefix.is_empty()).then_some(prefix)
}

impl PolicyEngine for RuleEngine {
    fn evaluate_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.evaluate_domain_with_source(domain)
    }

    fn evaluate_normalized_domain_with_source(&self, domain: &str) -> Option<DomainDecision> {
        self.evaluate_normalized_domain_with_source(domain)
    }

    fn matching_blocklists(&self, domain: &str) -> Vec<String> {
        RuleEngine::matching_blocklists(self, domain)
    }

    fn matching_normalized_blocklists(&self, domain: &str) -> Vec<String> {
        RuleEngine::matching_normalized_blocklists(self, domain)
    }
}
