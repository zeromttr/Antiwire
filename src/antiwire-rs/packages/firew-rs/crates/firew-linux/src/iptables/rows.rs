//! Rendering rules as `iptables` rule specifications.

use std::fmt::Write as _;

use firew_core::{Action, Direction, Error, Protocol, Rule};
use firew_sys::{alternatives, split_directions, PartMarkers};

use super::{IptablesBackend, RuleVariant};

impl IptablesBackend {
    fn build_rule_spec(&self, rule: &Rule, variant: &RuleVariant<'_>) -> String {
        let mut spec = String::with_capacity(
            64 + self.config.name_prefix.len()
                + self.config.application_name.len()
                + rule.logical_key().as_str().len(),
        );

        if let Some(set_name) = variant.remote_set {
            let direction = if variant.inbound { "src" } else { "dst" };
            write!(spec, "-m set --match-set {set_name} {direction}")
                .expect("writing to a String cannot fail");
        } else if let Some(net) = variant.remote_address {
            let flag = if variant.inbound { "-s" } else { "-d" };
            write!(spec, "{flag} {net}").expect("writing to a String cannot fail");
        }
        if let Some(net) = variant.local_address {
            push_separator(&mut spec);
            let flag = if variant.inbound { "-d" } else { "-s" };
            write!(spec, "{flag} {net}").expect("writing to a String cannot fail");
        }

        if let Some(proto) = rule.protocol().number() {
            push_separator(&mut spec);
            match rule.protocol() {
                Protocol::Tcp => spec.push_str("-p tcp"),
                Protocol::Udp => spec.push_str("-p udp"),
                Protocol::IcmpV4 => spec.push_str("-p icmp"),
                Protocol::IcmpV6 => spec.push_str("-p ipv6-icmp"),
                Protocol::Any => unreachable!("Protocol::Any has no protocol number"),
                Protocol::Other(_) => {
                    write!(spec, "-p {proto}").expect("writing to a String cannot fail");
                }
            }
        }

        if let Some(port) = variant.remote_port {
            push_separator(&mut spec);
            let flag = if variant.inbound {
                "--sport"
            } else {
                "--dport"
            };
            if port.start() == port.end() {
                write!(spec, "{flag} {}", port.start()).expect("writing to a String cannot fail");
            } else {
                write!(spec, "{flag} {}:{}", port.start(), port.end())
                    .expect("writing to a String cannot fail");
            }
        }
        if let Some(port) = variant.local_port {
            push_separator(&mut spec);
            let flag = if variant.inbound {
                "--dport"
            } else {
                "--sport"
            };
            if port.start() == port.end() {
                write!(spec, "{flag} {}", port.start()).expect("writing to a String cannot fail");
            } else {
                write!(spec, "{flag} {}:{}", port.start(), port.end())
                    .expect("writing to a String cannot fail");
            }
        }

        push_separator(&mut spec);
        spec.push_str("-m comment --comment \"");
        spec.push_str(&variant.marker);
        spec.push('"');

        push_separator(&mut spec);
        match rule.action() {
            Action::Allow => spec.push_str("-j ACCEPT"),
            Action::Block => spec.push_str("-j DROP"),
            Action::Reject => spec.push_str("-j REJECT"),
        }

        spec
    }

    /// Rows for a rule whose remote addresses live in an ipset: expands across
    /// directions, local addresses, remote ports, and local ports.
    pub(crate) fn build_set_rule_rows(
        &self,
        rule: &Rule,
        set_name: &str,
    ) -> Result<Vec<(String, String)>, Error> {
        let directions = split_directions(rule.direction());
        let local_addresses = alternatives(rule.local_addresses());
        let remote_ports = alternatives(rule.remote_ports());
        let local_ports = alternatives(rule.local_ports());
        let total_rows =
            directions.len() * local_addresses.len() * remote_ports.len() * local_ports.len();
        let namespace = self.config.managed_namespace();
        let mut markers = PartMarkers::new("iptables", rule.logical_key(), &namespace, total_rows)?;
        let mut rows = Vec::with_capacity(total_rows);
        for &direction in directions {
            let inbound = direction == Direction::Inbound;
            for &local_address in &local_addresses {
                for &remote_port in &remote_ports {
                    for &local_port in &local_ports {
                        let variant = RuleVariant {
                            inbound,
                            remote_set: Some(set_name),
                            remote_address: None,
                            local_address,
                            remote_port,
                            local_port,
                            marker: markers.encode_next()?,
                        };
                        let spec = self.build_rule_spec(rule, &variant);
                        rows.push((self.chain(inbound).to_owned(), spec));
                    }
                }
            }
        }
        Ok(rows)
    }

    pub(crate) fn build_rule_rows(&self, rule: &Rule) -> Result<Vec<(String, String)>, Error> {
        let directions = split_directions(rule.direction());
        let remote_addresses = alternatives(rule.remote_addresses());
        let local_addresses = alternatives(rule.local_addresses());
        let remote_ports = alternatives(rule.remote_ports());
        let local_ports = alternatives(rule.local_ports());
        let total_rows = directions.len()
            * remote_addresses.len()
            * local_addresses.len()
            * remote_ports.len()
            * local_ports.len();
        let namespace = self.config.managed_namespace();
        let mut markers = PartMarkers::new("iptables", rule.logical_key(), &namespace, total_rows)?;
        let mut rows = Vec::with_capacity(total_rows);
        for &direction in directions {
            let inbound = direction == Direction::Inbound;
            for &remote_address in &remote_addresses {
                for &local_address in &local_addresses {
                    for &remote_port in &remote_ports {
                        for &local_port in &local_ports {
                            let variant = RuleVariant {
                                inbound,
                                remote_set: None,
                                remote_address,
                                local_address,
                                remote_port,
                                local_port,
                                marker: markers.encode_next()?,
                            };
                            let spec = self.build_rule_spec(rule, &variant);
                            rows.push((self.chain(inbound).to_owned(), spec));
                        }
                    }
                }
            }
        }
        Ok(rows)
    }
}
fn push_separator(output: &mut String) {
    if !output.is_empty() {
        output.push(' ');
    }
}
