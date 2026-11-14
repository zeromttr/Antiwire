//! Portable firewall rule definition.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::action::Action;
use crate::direction::Direction;
use crate::domain::normalize_domain;
use crate::error::Error;
use crate::port_range::PortRange;
use crate::protocol::Protocol;
use crate::rule_key::RuleKey;

/// Maximum number of alternatives accepted in one matcher field.
pub const MAX_MATCHERS_PER_FIELD: usize = 64;
/// Maximum number of native rows one logical rule may require.
pub const MAX_NATIVE_EXPANSION: usize = 256;
/// Maximum number of remote addresses accepted in [`AddressSetMode::Set`].
pub const MAX_ADDRESS_SET_ENTRIES: usize = 65_536;
/// Maximum number of bytes in a non-semantic human-readable label.
pub const MAX_RULE_LABEL_LEN: usize = 128;
const MAX_PACKAGE_SID_LEN: usize = 256;

mod builder;
mod repr;
#[cfg(test)]
mod tests;
mod validate;

pub use builder::RuleBuilder;
pub use validate::cartesian_exceeds_limits;

/// How `remote_addresses` expands into native firewall rows.
///
/// Most backends emit one native row per remote address, so the portable
/// [`MAX_MATCHERS_PER_FIELD`] and [`MAX_NATIVE_EXPANSION`] caps keep a single
/// logical rule from exploding into thousands of native rows. Some backends
/// instead express many addresses as one native object — a comma-separated
/// Windows `RemoteAddresses` field, an nftables named set, a pf table, or an
/// ipset — for which those caps are the wrong shape entirely.
///
/// [`AddressSetMode::Set`] opts a rule into that representation. It is not a
/// matcher: a `Set` rule and a `Cartesian` rule holding the same addresses
/// match exactly the same traffic, which is why [`Rule`]'s `PartialEq` ignores
/// it. Backends that cannot express a set natively must reject `Set` rules
/// from `validate_rule` so the caller knows to chunk instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressSetMode {
    /// Remote addresses participate in the Cartesian expansion and obey
    /// [`MAX_MATCHERS_PER_FIELD`].
    #[default]
    Cartesian,
    /// Remote addresses form one native set matcher: exempt from
    /// [`MAX_MATCHERS_PER_FIELD`], counted as a single factor in
    /// [`Rule::native_expansion`], and bounded by [`MAX_ADDRESS_SET_ENTRIES`].
    Set,
}

/// Portable firewall rule consumed by all platform backends.
#[derive(Clone, Debug)]
pub struct Rule {
    inner: Arc<RuleInner>,
}

#[derive(Debug)]
struct RuleInner {
    logical_key: RuleKey,
    label: Option<String>,
    action: Action,
    direction: Direction,
    protocol: Protocol,
    remote_addresses: Vec<IpNet>,
    local_addresses: Vec<IpNet>,
    remote_ports: Vec<PortRange>,
    local_ports: Vec<PortRange>,
    application_path: Option<PathBuf>,
    package_sid: Option<String>,
    remote_domains: Vec<String>,
    address_set_mode: AddressSetMode,
}

impl Rule {
    /// Stable logical key for install/remove correlation.
    #[must_use]
    pub fn logical_key(&self) -> &RuleKey {
        &self.inner.logical_key
    }

    /// Optional non-semantic display label.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.inner.label.as_deref()
    }

    /// Rule action.
    #[must_use]
    pub fn action(&self) -> Action {
        self.inner.action
    }

    /// Rule direction.
    #[must_use]
    pub fn direction(&self) -> Direction {
        self.inner.direction
    }

    /// Selected protocol.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.inner.protocol
    }

    /// Remote address matchers.
    #[must_use]
    pub fn remote_addresses(&self) -> &[IpNet] {
        &self.inner.remote_addresses
    }

    /// How [`Self::remote_addresses`] expands into native rows.
    #[must_use]
    pub fn address_set_mode(&self) -> AddressSetMode {
        self.inner.address_set_mode
    }

    /// Local address matchers.
    #[must_use]
    pub fn local_addresses(&self) -> &[IpNet] {
        &self.inner.local_addresses
    }

    /// Remote port matchers.
    #[must_use]
    pub fn remote_ports(&self) -> &[PortRange] {
        &self.inner.remote_ports
    }

    /// Local port matchers.
    #[must_use]
    pub fn local_ports(&self) -> &[PortRange] {
        &self.inner.local_ports
    }

    /// Application executable path matcher.
    #[must_use]
    pub fn application_path(&self) -> Option<&Path> {
        self.inner.application_path.as_deref()
    }

    /// Windows package SID matcher.
    #[must_use]
    pub fn package_sid(&self) -> Option<&str> {
        self.inner.package_sid.as_deref()
    }

    /// Remote domain matchers (resolved to IP sets by the facade).
    #[must_use]
    pub fn remote_domains(&self) -> &[String] {
        &self.inner.remote_domains
    }

    fn construct_and_validate(mut inner: RuleInner) -> Result<Self, Error> {
        inner.protocol = inner.protocol.canonicalize();
        inner.remote_addresses = canonicalize_addresses(
            inner.remote_addresses,
            inner.address_set_mode == AddressSetMode::Set,
        );
        inner.local_addresses = canonicalize_addresses(inner.local_addresses, false);
        inner.remote_ports.sort_unstable();
        inner.remote_ports.dedup();
        inner.local_ports.sort_unstable();
        inner.local_ports.dedup();
        inner.remote_domains = inner
            .remote_domains
            .into_iter()
            .map(|domain| normalize_domain(&domain))
            .collect::<Result<Vec<_>, _>>()?;
        inner.remote_domains.sort_unstable();
        inner.remote_domains.dedup();

        let rule = Self {
            inner: Arc::new(inner),
        };
        rule.validate()?;
        Ok(rule)
    }
}

fn canonicalize_addresses(addresses: Vec<IpNet>, collapse_contained: bool) -> Vec<IpNet> {
    let mut nets: Vec<IpNet> = addresses.into_iter().map(|net| net.trunc()).collect();
    nets.sort_unstable();
    nets.dedup();
    if !collapse_contained || nets.len() <= 1 {
        return nets;
    }
    let mut collapsed: Vec<IpNet> = Vec::with_capacity(nets.len());
    for net in nets {
        if !collapsed.last().is_some_and(|prev| prev.contains(&net)) {
            collapsed.push(net);
        }
    }
    collapsed
}

/// Compares matchers only.
///
/// [`AddressSetMode`] is deliberately excluded: it selects a native
/// *representation*, not what traffic the rule matches, and native read-back
/// cannot always recover which mode produced a rule. Including it would make
/// [`crate`] consumers such as `reconcile` see an unchanged rule as modified on
/// every pass.
impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.inner.logical_key == other.inner.logical_key
            && self.inner.action == other.inner.action
            && self.inner.direction == other.inner.direction
            && self.inner.protocol == other.inner.protocol
            && self.inner.remote_addresses == other.inner.remote_addresses
            && self.inner.local_addresses == other.inner.local_addresses
            && self.inner.remote_ports == other.inner.remote_ports
            && self.inner.local_ports == other.inner.local_ports
            && self.inner.application_path == other.inner.application_path
            && self.inner.package_sid == other.inner.package_sid
            && self.inner.remote_domains == other.inner.remote_domains
    }
}

impl Eq for Rule {}
