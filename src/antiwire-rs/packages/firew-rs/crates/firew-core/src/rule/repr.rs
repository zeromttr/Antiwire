//! Serialized form of a rule.

use std::path::{Path, PathBuf};

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::action::Action;
use crate::direction::Direction;
use crate::port_range::PortRange;
use crate::protocol::Protocol;
use crate::rule_key::RuleKey;

use super::{AddressSetMode, Rule, RuleInner};

#[derive(Serialize)]
struct RuleRef<'a> {
    logical_key: &'a RuleKey,
    label: Option<&'a str>,
    action: Action,
    direction: Direction,
    protocol: Protocol,
    remote_addresses: &'a [IpNet],
    local_addresses: &'a [IpNet],
    remote_ports: &'a [PortRange],
    local_ports: &'a [PortRange],
    application_path: Option<&'a Path>,
    package_sid: Option<&'a str>,
    remote_domains: &'a [String],
    address_set_mode: AddressSetMode,
}

#[derive(Deserialize)]
struct RuleRepr {
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
    /// Absent in payloads written before address sets existed; those rules were
    /// Cartesian and stay capped at [`MAX_MATCHERS_PER_FIELD`].
    #[serde(default)]
    address_set_mode: AddressSetMode,
}

impl Serialize for Rule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RuleRef {
            logical_key: self.logical_key(),
            label: self.label(),
            action: self.action(),
            direction: self.direction(),
            protocol: self.protocol(),
            remote_addresses: self.remote_addresses(),
            local_addresses: self.local_addresses(),
            remote_ports: self.remote_ports(),
            local_ports: self.local_ports(),
            application_path: self.application_path(),
            package_sid: self.package_sid(),
            remote_domains: self.remote_domains(),
            address_set_mode: self.address_set_mode(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let repr = RuleRepr::deserialize(deserializer)?;
        Self::construct_and_validate(RuleInner {
            logical_key: repr.logical_key,
            label: repr.label,
            action: repr.action,
            direction: repr.direction,
            protocol: repr.protocol,
            remote_addresses: repr.remote_addresses,
            local_addresses: repr.local_addresses,
            remote_ports: repr.remote_ports,
            local_ports: repr.local_ports,
            application_path: repr.application_path,
            package_sid: repr.package_sid,
            remote_domains: repr.remote_domains,
            address_set_mode: repr.address_set_mode,
        })
        .map_err(serde::de::Error::custom)
    }
}
