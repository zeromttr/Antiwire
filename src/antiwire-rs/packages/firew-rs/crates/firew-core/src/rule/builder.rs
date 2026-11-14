//! Building rules.

use std::path::PathBuf;

use ipnet::IpNet;

use crate::action::Action;
use crate::direction::Direction;
use crate::domain::normalize_domain;
use crate::error::Error;
use crate::port_range::PortRange;
use crate::protocol::Protocol;
use crate::rule_key::RuleKey;

use super::{AddressSetMode, Rule, RuleInner};

impl Rule {
    /// Creates a rule builder with required fields.
    #[must_use]
    pub fn builder(
        logical_key: impl Into<String>,
        action: Action,
        direction: Direction,
    ) -> RuleBuilder {
        RuleBuilder::new(logical_key, action, direction)
    }

    /// A builder holding every field of this rule, for deriving a changed copy.
    #[must_use]
    pub fn to_builder(&self) -> RuleBuilder {
        let inner = &self.inner;
        RuleBuilder {
            logical_key: inner.logical_key.as_str().to_owned(),
            label: inner.label.clone(),
            action: inner.action,
            direction: inner.direction,
            protocol: inner.protocol,
            remote_addresses: inner.remote_addresses.clone(),
            local_addresses: inner.local_addresses.clone(),
            remote_ports: inner.remote_ports.clone(),
            local_ports: inner.local_ports.clone(),
            application_path: inner.application_path.clone(),
            package_sid: inner.package_sid.clone(),
            remote_domains: inner.remote_domains.clone(),
            address_set_mode: inner.address_set_mode,
        }
    }
}

/// Builder for [`Rule`].
#[derive(Clone, Debug)]
pub struct RuleBuilder {
    logical_key: String,
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

impl RuleBuilder {
    #[must_use]
    fn new(logical_key: impl Into<String>, action: Action, direction: Direction) -> Self {
        Self {
            logical_key: logical_key.into(),
            label: None,
            action,
            direction,
            protocol: Protocol::Any,
            remote_addresses: Vec::new(),
            local_addresses: Vec::new(),
            remote_ports: Vec::new(),
            local_ports: Vec::new(),
            application_path: None,
            package_sid: None,
            remote_domains: Vec::new(),
            address_set_mode: AddressSetMode::Cartesian,
        }
    }

    /// Replaces the direction.
    #[must_use]
    pub fn direction(mut self, direction: Direction) -> Self {
        self.direction = direction;
        self
    }

    /// Drops every remote address and returns to [`AddressSetMode::Cartesian`].
    #[must_use]
    pub fn without_remote_addresses(mut self) -> Self {
        self.remote_addresses.clear();
        self.address_set_mode = AddressSetMode::Cartesian;
        self
    }

    /// Drops every remote domain.
    #[must_use]
    pub fn without_remote_domains(mut self) -> Self {
        self.remote_domains.clear();
        self
    }

    /// Sets a non-semantic human-readable label.
    #[must_use]
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// Sets protocol matcher.
    #[must_use]
    pub fn protocol(mut self, protocol: Protocol) -> Self {
        self.protocol = protocol.canonicalize();
        self
    }

    /// Adds a remote IP or CIDR matcher.
    #[must_use]
    pub fn remote_address(mut self, net: IpNet) -> Self {
        self.remote_addresses.push(net);
        self
    }

    /// Adds remote addresses as one native set matcher.
    ///
    /// Switches the rule to [`AddressSetMode::Set`], lifting the
    /// [`MAX_MATCHERS_PER_FIELD`](super::MAX_MATCHERS_PER_FIELD) cap in favour
    /// of [`MAX_ADDRESS_SET_ENTRIES`](super::MAX_ADDRESS_SET_ENTRIES) and
    /// collapsing the remote-address factor in [`Rule::native_expansion`].
    /// Backends that cannot express a set reject the rule at validation, so
    /// callers should consult the backend's capability before using this.
    ///
    /// Addresses are sorted and deduplicated by [`Self::build`].
    #[must_use]
    pub fn remote_address_set(mut self, nets: impl IntoIterator<Item = IpNet>) -> Self {
        self.remote_addresses.extend(nets);
        self.address_set_mode = AddressSetMode::Set;
        self
    }

    /// Adds a local IP or CIDR matcher.
    #[must_use]
    pub fn local_address(mut self, net: IpNet) -> Self {
        self.local_addresses.push(net);
        self
    }

    /// Adds a remote port matcher.
    #[must_use]
    pub fn remote_port(mut self, range: PortRange) -> Self {
        self.remote_ports.push(range);
        self
    }

    /// Adds a local port matcher.
    #[must_use]
    pub fn local_port(mut self, range: PortRange) -> Self {
        self.local_ports.push(range);
        self
    }

    /// Sets application executable path matcher.
    #[must_use]
    pub fn application_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.application_path = Some(path.into());
        self
    }

    /// Sets Windows package SID matcher.
    #[must_use]
    pub fn package_sid(mut self, sid: impl Into<String>) -> Self {
        self.package_sid = Some(sid.into());
        self
    }

    /// Adds a remote domain matcher.
    ///
    /// # Errors
    /// Returns an error when the domain name is invalid.
    pub fn remote_domain(mut self, domain: impl AsRef<str>) -> Result<Self, Error> {
        let normalized = normalize_domain(domain.as_ref())?;
        self.remote_domains.push(normalized);
        Ok(self)
    }

    /// Builds and validates the rule.
    ///
    /// # Errors
    /// Returns an error when rule validation fails.
    pub fn build(self) -> Result<Rule, Error> {
        Rule::construct_and_validate(RuleInner {
            logical_key: RuleKey::try_from(self.logical_key)?,
            label: self.label,
            action: self.action,
            direction: self.direction,
            protocol: self.protocol,
            remote_addresses: self.remote_addresses,
            local_addresses: self.local_addresses,
            remote_ports: self.remote_ports,
            local_ports: self.local_ports,
            application_path: self.application_path,
            package_sid: self.package_sid,
            remote_domains: self.remote_domains,
            address_set_mode: self.address_set_mode,
        })
    }
}
