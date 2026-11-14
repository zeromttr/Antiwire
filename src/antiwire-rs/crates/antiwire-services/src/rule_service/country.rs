//! Country blocks: one rule covering every network of a country.

use std::net::IpAddr;
use std::sync::Arc;

use antiwire_policy::{CountrySnapshot, RuleTargetKind};
use antiwire_store::{FirewallRule, Store, StoreError};
use ipnet::IpNet;
use time::OffsetDateTime;

use super::change::RuleChange;
use super::error::{Result, RuleServiceError};
use super::request::{CountryRuleSummary, CountrySelector, NewCountryBlock};
use super::service::RuleService;

/// Upper bound on networks in one country block.
///
/// Matches the largest address set the firewall backends accept, so an
/// oversized list is rejected with a clear message instead of failing later.
const MAX_COUNTRY_NETWORKS: usize = 65_536;

pub(super) fn normalize_country_code(code: &str) -> Result<String> {
    let trimmed = code.trim().to_ascii_uppercase();
    if trimmed.len() != 2 || !trimmed.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(RuleServiceError::invalid(format!(
            "country code must be two letters (ISO-3166-1 alpha-2), got {code:?}"
        )));
    }
    Ok(trimmed)
}

/// Parses, normalizes, sorts, and deduplicates a country's networks.
///
/// Sorting and deduplicating here means the saved payload, the policy trie,
/// and the native rule all agree on the same canonical list.
pub(super) fn normalize_country_networks(cidrs: &[String]) -> Result<Arc<[IpNet]>> {
    if cidrs.is_empty() {
        return Err(RuleServiceError::invalid(
            "a country block needs at least one network",
        ));
    }
    if cidrs.len() > MAX_COUNTRY_NETWORKS {
        return Err(RuleServiceError::invalid(format!(
            "a country block accepts at most {MAX_COUNTRY_NETWORKS} networks, got {}",
            cidrs.len()
        )));
    }

    let mut networks = Vec::with_capacity(cidrs.len());
    for cidr in cidrs {
        let trimmed = cidr.trim();
        let network = trimmed
            .parse::<IpNet>()
            .map(|net| net.trunc())
            .or_else(|_| {
                trimmed.parse::<IpAddr>().map(|addr| {
                    let prefix = if addr.is_ipv4() { 32 } else { 128 };
                    IpNet::new(addr, prefix).expect("full-length prefix is valid")
                })
            })
            .map_err(|_| {
                RuleServiceError::invalid(format!("invalid network in country block: {cidr:?}"))
            })?;
        networks.push(network);
    }
    networks.sort_unstable();
    networks.dedup();
    Ok(networks.into())
}

/// Summaries of `countries`, saved country rows, with their network counts.
pub(super) fn country_summaries(
    store: &Store,
    countries: &[FirewallRule],
) -> Result<Vec<CountryRuleSummary>> {
    let counts = store.count_rule_cidrs_by_rule()?;
    Ok(countries
        .iter()
        .map(|rule| CountryRuleSummary {
            id: rule.id,
            code: rule.target_value.clone(),
            verdict: rule.action,
            direction: rule.direction,
            network_count: counts
                .get(&rule.id)
                .and_then(|count| u32::try_from(*count).ok())
                .unwrap_or(0),
        })
        .collect())
}

impl RuleService {
    /// Saves a country block and puts it into effect.
    ///
    /// # Errors
    ///
    /// [`RuleServiceError::Invalid`] for an invalid code or network list, and
    /// [`RuleServiceError::Conflict`] for a country already blocked. Otherwise
    /// a store or firewall failure; the change is then undone.
    pub fn add_country_rule(&self, block: &NewCountryBlock) -> Result<CountryRuleSummary> {
        let guard = self.begin_change();
        self.require_packet_rules()?;
        let code = normalize_country_code(&block.code)?;
        let networks = normalize_country_networks(&block.networks)?;
        if self.find_country(&code)?.is_some() {
            return Err(RuleServiceError::Conflict(format!(
                "{code} is already blocked"
            )));
        }

        let stored = FirewallRule {
            id: 0,
            target_type: RuleTargetKind::Country,
            target_value: code.clone(),
            action: block.verdict,
            direction: block.direction,
            created_at: OffsetDateTime::now_utc(),
        };
        let saved: Vec<String> = networks.iter().map(ToString::to_string).collect();
        let network_count = u32::try_from(saved.len()).unwrap_or(u32::MAX);
        RuleChange::run(&guard, |change| {
            let id = change.insert_country_row(&stored, &saved)?;
            change.upsert_country(&CountrySnapshot::new(
                id,
                code.clone(),
                networks,
                block.verdict,
                block.direction,
            ))?;
            Ok(CountryRuleSummary {
                id,
                code,
                verdict: block.verdict,
                direction: block.direction,
                network_count,
            })
        })
    }

    /// Removes the country block `selector` names. Returns `false` when there
    /// is none.
    ///
    /// # Errors
    ///
    /// [`RuleServiceError::Invalid`] for an invalid code, or an id naming a
    /// rule that is not a country block. Otherwise a store or firewall
    /// failure; the change is then undone.
    pub fn remove_country_rule(&self, selector: &CountrySelector) -> Result<bool> {
        let guard = self.begin_change();
        let stored = match selector {
            CountrySelector::Id(id) => match self.store.get_rule(*id) {
                Ok(rule) => rule,
                Err(StoreError::RuleNotFound(_)) => return Ok(false),
                Err(error) => return Err(error.into()),
            },
            CountrySelector::Code(code) => {
                match self.find_country(&normalize_country_code(code)?)? {
                    Some(rule) => rule,
                    None => return Ok(false),
                }
            }
        };
        if stored.target_type != RuleTargetKind::Country {
            return Err(RuleServiceError::invalid(format!(
                "rule {} is not a country block",
                stored.id
            )));
        }
        RuleChange::run(&guard, |change| {
            change.remove_country(stored.id)?;
            change.delete_row(stored.id)?;
            Ok(true)
        })
    }

    fn find_country(&self, code: &str) -> Result<Option<FirewallRule>> {
        Ok(self
            .store
            .list_rules()?
            .into_iter()
            .find(|rule| rule.target_type == RuleTargetKind::Country && rule.target_value == code))
    }
}
