//! Rendering managed rules as PF anchor text.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use firew_core::{
    Action, AddressSetMode, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey,
};
use firew_sys::{address_pairs, alternatives, split_directions, ManagedNamespace, PartMarkers};
use ipnet::IpNet;

use super::{table_name_for, MAX_TABLE_ENTRIES};

/// Renders the complete anchor ruleset for all managed rules (both Set and Cartesian)
/// in `namespace`.
///
/// Emitting tables and all filter rules into one anchor ruleset allows `pfctl -a <anchor> -f -`
/// to commit both representations in a single atomic kernel load.
///
/// # Errors
///
/// Returns an error when a rule exceeds PF table or marker limits.
pub fn render_full_anchor(
    rules: &BTreeMap<RuleKey, Rule>,
    namespace: &ManagedNamespace,
) -> Result<String, Error> {
    let mut text = String::new();

    for (key, rule) in rules {
        if rule.address_set_mode() != AddressSetMode::Set {
            continue;
        }
        if rule.remote_addresses().len() > MAX_TABLE_ENTRIES {
            return Err(Error::new(
                ErrorKind::LimitExceeded,
                format!(
                    "pf table would hold {} entries; maximum is {MAX_TABLE_ENTRIES}",
                    rule.remote_addresses().len()
                ),
            )
            .with_logical_key(key));
        }
        let table = table_name_for(namespace, key);
        writeln!(text, "table <{table}> persist {{ {} }}", join_nets(rule))
            .expect("writing to a String cannot fail");
    }

    for (key, rule) in rules {
        if rule.address_set_mode() == AddressSetMode::Set {
            let table = table_name_for(namespace, key);
            for line in set_rule_lines(rule, &table, namespace)? {
                text.push_str(&line);
                text.push('\n');
            }
        } else {
            for line in cartesian_rule_lines(rule, namespace)? {
                text.push_str(&line);
                text.push('\n');
            }
        }
    }

    Ok(text)
}

/// Renders the anchor ruleset for every set-mode rule in `namespace`.
///
/// # Errors
///
/// Returns an error when a rule holds more addresses than a table may contain.
#[cfg(test)]
pub fn render_anchor(
    rules: &BTreeMap<RuleKey, Rule>,
    namespace: &ManagedNamespace,
) -> Result<String, Error> {
    let set_only: BTreeMap<RuleKey, Rule> = rules
        .iter()
        .filter(|(_, rule)| rule.address_set_mode() == AddressSetMode::Set)
        .map(|(k, r)| (k.clone(), r.clone()))
        .collect();
    render_full_anchor(&set_only, namespace)
}

fn join_nets(rule: &Rule) -> String {
    let mut out = String::with_capacity(rule.remote_addresses().len() * 20);
    for (index, net) in rule.remote_addresses().iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&render_net(*net));
    }
    out
}

/// pf writes a host address without its `/32` or `/128` suffix.
fn render_net(net: IpNet) -> String {
    let canonical = net.trunc();
    let max_prefix = if canonical.addr().is_ipv4() { 32 } else { 128 };
    if canonical.prefix_len() == max_prefix {
        canonical.addr().to_string()
    } else {
        canonical.to_string()
    }
}

fn set_rule_lines(
    rule: &Rule,
    table: &str,
    namespace: &ManagedNamespace,
) -> Result<Vec<String>, Error> {
    let directions = split_directions(rule.direction());
    let has_remote_v4 = rule.remote_addresses().iter().any(|n| n.addr().is_ipv4());
    let has_remote_v6 = rule.remote_addresses().iter().any(|n| n.addr().is_ipv6());

    let local_addresses: Vec<Option<&IpNet>> = if rule.local_addresses().is_empty() {
        vec![None]
    } else {
        rule.local_addresses()
            .iter()
            .filter(|local| {
                (local.addr().is_ipv4() && has_remote_v4)
                    || (local.addr().is_ipv6() && has_remote_v6)
            })
            .map(Some)
            .collect()
    };
    let remote_ports = alternatives(rule.remote_ports());
    let local_ports = alternatives(rule.local_ports());

    let total_rows =
        directions.len() * local_addresses.len() * remote_ports.len() * local_ports.len();
    let mut markers = PartMarkers::new("PF", rule.logical_key(), namespace, total_rows)?;

    let remote_table_target = format!("<{table}>");
    let mut lines = Vec::with_capacity(total_rows);

    for &direction in directions {
        for &local_net in &local_addresses {
            for &remote_port in &remote_ports {
                for &local_port in &local_ports {
                    let marker = markers.encode_next()?;
                    let local_target =
                        local_net.map_or_else(|| "any".to_owned(), |n| render_net(*n));
                    let af = set_addr_family_word(rule, local_net);
                    lines.push(format_pf_rule_line(&PfRuleLine {
                        action: rule.action(),
                        direction,
                        addr_family: af,
                        protocol: rule.protocol(),
                        remote_target: &remote_table_target,
                        local_target: &local_target,
                        remote_port,
                        local_port,
                        marker: &marker,
                    }));
                }
            }
        }
    }

    Ok(lines)
}

fn cartesian_rule_lines(rule: &Rule, namespace: &ManagedNamespace) -> Result<Vec<String>, Error> {
    let directions = split_directions(rule.direction());
    let remote_ports = alternatives(rule.remote_ports());
    let local_ports = alternatives(rule.local_ports());

    let address_pairs = address_pairs(rule);

    let total_rows =
        directions.len() * address_pairs.len() * remote_ports.len() * local_ports.len();
    let mut markers = PartMarkers::new("PF", rule.logical_key(), namespace, total_rows)?;

    let mut lines = Vec::with_capacity(total_rows);

    for &direction in directions {
        for &(remote_net, local_net) in &address_pairs {
            for &remote_port in &remote_ports {
                for &local_port in &local_ports {
                    let marker = markers.encode_next()?;
                    let remote_target =
                        remote_net.map_or_else(|| "any".to_owned(), |n| render_net(*n));
                    let local_target =
                        local_net.map_or_else(|| "any".to_owned(), |n| render_net(*n));
                    let af = cartesian_addr_family_word(rule.protocol(), remote_net, local_net);
                    lines.push(format_pf_rule_line(&PfRuleLine {
                        action: rule.action(),
                        direction,
                        addr_family: af,
                        protocol: rule.protocol(),
                        remote_target: &remote_target,
                        local_target: &local_target,
                        remote_port,
                        local_port,
                        marker: &marker,
                    }));
                }
            }
        }
    }

    Ok(lines)
}

pub(super) fn set_addr_family_word(rule: &Rule, local_net: Option<&IpNet>) -> Option<&'static str> {
    if let Some(local) = local_net {
        return Some(if local.addr().is_ipv4() {
            "inet"
        } else {
            "inet6"
        });
    }
    match rule.protocol() {
        Protocol::IcmpV4 => return Some("inet"),
        Protocol::IcmpV6 => return Some("inet6"),
        _ => {}
    }
    let all_v4 = rule.remote_addresses().iter().all(|n| n.addr().is_ipv4());
    let all_v6 = rule.remote_addresses().iter().all(|n| n.addr().is_ipv6());
    if all_v4 && !rule.remote_addresses().is_empty() {
        Some("inet")
    } else if all_v6 && !rule.remote_addresses().is_empty() {
        Some("inet6")
    } else {
        None
    }
}

pub(super) fn cartesian_addr_family_word(
    protocol: Protocol,
    remote_net: Option<&IpNet>,
    local_net: Option<&IpNet>,
) -> Option<&'static str> {
    if let Some(net) = remote_net.or(local_net) {
        return Some(if net.addr().is_ipv4() {
            "inet"
        } else {
            "inet6"
        });
    }
    match protocol {
        Protocol::IcmpV4 => Some("inet"),
        Protocol::IcmpV6 => Some("inet6"),
        _ => None,
    }
}

/// One rendered PF rule: a single direction, endpoint pair, and port pair.
struct PfRuleLine<'a> {
    action: Action,
    direction: Direction,
    addr_family: Option<&'a str>,
    protocol: Protocol,
    remote_target: &'a str,
    local_target: &'a str,
    remote_port: Option<&'a PortRange>,
    local_port: Option<&'a PortRange>,
    marker: &'a str,
}

fn format_pf_rule_line(line: &PfRuleLine<'_>) -> String {
    let PfRuleLine {
        action,
        direction,
        addr_family,
        protocol,
        remote_target,
        local_target,
        remote_port,
        local_port,
        marker,
    } = *line;
    let action_word = match action {
        Action::Allow => "pass",
        Action::Block => "block drop",
        Action::Reject => "block return",
    };
    let dir_word = match direction {
        Direction::Inbound => "in",
        Direction::Outbound | Direction::Both => "out",
    };

    let mut line = format!("{action_word} {dir_word} quick");
    if let Some(af) = addr_family {
        write!(line, " {af}").expect("writing to a String cannot fail");
    }
    match protocol {
        Protocol::Any => {}
        Protocol::Tcp => line.push_str(" proto tcp"),
        Protocol::Udp => line.push_str(" proto udp"),
        Protocol::IcmpV4 => line.push_str(" proto icmp"),
        Protocol::IcmpV6 => line.push_str(" proto icmp6"),
        Protocol::Other(number) => {
            write!(line, " proto {number}").expect("writing to a String cannot fail");
        }
    }

    let (from_target, from_port, to_target, to_port) = match direction {
        Direction::Inbound => (remote_target, remote_port, local_target, local_port),
        Direction::Outbound | Direction::Both => {
            (local_target, local_port, remote_target, remote_port)
        }
    };

    write!(line, " from {from_target}").expect("writing to a String cannot fail");
    if let Some(port) = from_port {
        write_port_clause(&mut line, *port);
    }
    write!(line, " to {to_target}").expect("writing to a String cannot fail");
    if let Some(port) = to_port {
        write_port_clause(&mut line, *port);
    }
    write!(line, " label \"{marker}\"").expect("writing to a String cannot fail");
    line
}

fn write_port_clause(line: &mut String, port: PortRange) {
    if port.is_single() {
        write!(line, " port = {}", port.start()).expect("writing to a String cannot fail");
    } else {
        write!(line, " port {}:{}", port.start(), port.end())
            .expect("writing to a String cannot fail");
    }
}
