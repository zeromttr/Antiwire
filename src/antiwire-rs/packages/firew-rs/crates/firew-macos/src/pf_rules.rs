//! Conversion from [`firew_core::Rule`] to [`pfctl::FilterRule`].

use std::collections::BTreeMap;
use std::net::IpAddr;

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use firew_sys::{address_pairs, alternatives, ManagedNamespace, PartMarkers};
use ipnet::IpNet;
use ipnetwork::IpNetwork;
use pfctl::{
    AddrFamily, Direction as PfDirection, DropAction, Endpoint, FilterRule, FilterRuleAction,
    FilterRuleBuilder, Port, PortRangeModifier, PortUnaryModifier, Proto,
};

pub(crate) fn build_filter_rules(
    rules: &BTreeMap<RuleKey, Rule>,
    namespace: &ManagedNamespace,
) -> Result<Vec<FilterRule>, Error> {
    let mut out = Vec::new();
    for rule in rules.values() {
        // Set-mode rules are rendered as anchor text with a pf table; emitting
        // them here too would install the block twice.
        if rule.address_set_mode() == firew_core::AddressSetMode::Set {
            continue;
        }
        out.extend(rule_to_filter_rules(rule, namespace)?);
    }
    Ok(out)
}

fn rule_to_filter_rules(
    rule: &Rule,
    namespace: &ManagedNamespace,
) -> Result<Vec<FilterRule>, Error> {
    let mut out = Vec::new();
    let directions = match rule.direction() {
        Direction::Outbound => vec![PfDirection::Out],
        Direction::Inbound => vec![PfDirection::In],
        Direction::Both => vec![PfDirection::In, PfDirection::Out],
    };
    let remote_ports = alternatives(rule.remote_ports());
    let local_ports = alternatives(rule.local_ports());

    let address_pairs = address_pairs(rule);

    let rows = directions.len() * address_pairs.len() * remote_ports.len() * local_ports.len();
    let mut markers = PartMarkers::new("PF", rule.logical_key(), namespace, rows)?;
    for pf_dir in directions {
        for &(remote_net, local_net) in &address_pairs {
            for &remote_port in &remote_ports {
                for &local_port in &local_ports {
                    let marker = markers.encode_next()?;
                    out.push(build_single(
                        rule,
                        pf_dir,
                        remote_net,
                        local_net,
                        remote_port,
                        local_port,
                        &marker,
                    )?);
                }
            }
        }
    }
    Ok(out)
}

fn build_single(
    rule: &Rule,
    pf_dir: PfDirection,
    remote: Option<&IpNet>,
    local: Option<&IpNet>,
    remote_port: Option<&PortRange>,
    local_port: Option<&PortRange>,
    marker: &str,
) -> Result<FilterRule, Error> {
    let mut builder = FilterRuleBuilder::default();
    builder
        .action(map_action(rule.action()))
        .direction(pf_dir)
        .quick(true)
        .label(marker);

    if let Some(af) = addr_family_for(rule.protocol(), remote, local) {
        builder.af(af);
    }

    if let Some(proto) = map_protocol(rule.protocol()) {
        builder.proto(proto);
    }

    let remote_endpoint = endpoint(remote, remote_port)?;
    let local_endpoint = endpoint(local, local_port)?;

    match pf_dir {
        PfDirection::In => {
            builder.from(remote_endpoint).to(local_endpoint);
        }
        PfDirection::Out | PfDirection::Any => {
            builder.from(local_endpoint).to(remote_endpoint);
        }
    }

    builder.build().map_err(|error| map_pf_err(&error))
}

fn addr_family_for(
    protocol: Protocol,
    remote: Option<&IpNet>,
    local: Option<&IpNet>,
) -> Option<AddrFamily> {
    if let Some(net) = remote.or(local) {
        return Some(if net.addr().is_ipv4() {
            AddrFamily::Ipv4
        } else {
            AddrFamily::Ipv6
        });
    }
    match protocol {
        Protocol::IcmpV4 => Some(AddrFamily::Ipv4),
        Protocol::IcmpV6 => Some(AddrFamily::Ipv6),
        _ => None,
    }
}

fn endpoint(net: Option<&IpNet>, port: Option<&PortRange>) -> Result<Endpoint, Error> {
    let port = port.map_or_else(Port::default, |port| {
        if port.is_single() {
            Port::One(port.start(), PortUnaryModifier::Equal)
        } else {
            Port::Range(port.start(), port.end(), PortRangeModifier::Inclusive)
        }
    });
    let ip = net.map_or_else(
        || Ok(pfctl::Ip::default()),
        |net| ipnet_to_ipnetwork(net).map(pfctl::Ip::from),
    )?;
    Ok(Endpoint::new(ip, port))
}

fn map_action(action: Action) -> FilterRuleAction {
    match action {
        Action::Allow => FilterRuleAction::Pass,
        Action::Block => FilterRuleAction::Drop(DropAction::Drop),
        Action::Reject => FilterRuleAction::Drop(DropAction::Return),
    }
}

fn map_protocol(protocol: Protocol) -> Option<Proto> {
    match protocol {
        Protocol::Tcp => Some(Proto::Tcp),
        Protocol::Udp => Some(Proto::Udp),
        Protocol::IcmpV4 => Some(Proto::Icmp),
        Protocol::IcmpV6 => Some(Proto::IcmpV6),
        Protocol::Any | Protocol::Other(_) => None,
    }
}

fn ipnet_to_ipnetwork(net: &IpNet) -> Result<IpNetwork, Error> {
    let canonical = net.trunc();
    match canonical.addr() {
        IpAddr::V4(addr) => {
            let network = ipnetwork::Ipv4Network::new(addr, canonical.prefix_len())
                .map_err(|e| Error::new(ErrorKind::InvalidRule, format!("ipv4 network: {e}")))?;
            Ok(IpNetwork::V4(network))
        }
        IpAddr::V6(addr) => {
            let network = ipnetwork::Ipv6Network::new(addr, canonical.prefix_len())
                .map_err(|e| Error::new(ErrorKind::InvalidRule, format!("ipv6 network: {e}")))?;
            Ok(IpNetwork::V6(network))
        }
    }
}

fn map_pf_err(err: &pfctl::Error) -> Error {
    map_pf_err_kind(err, ErrorKind::Internal)
}

pub(crate) fn map_pf_err_kind(err: &pfctl::Error, fallback: ErrorKind) -> Error {
    let text = err.to_string();
    let lower = text.to_ascii_lowercase();
    let kind = if lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eacces")
        || lower.contains("eperm")
    {
        ErrorKind::PermissionDenied
    } else if lower.contains("invalid") {
        ErrorKind::InvalidRule
    } else {
        fallback
    };
    Error::new(kind, format!("pf: {text}"))
}
