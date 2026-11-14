//! Parsing listed `iptables` rows back into rules.

use std::collections::HashMap;
use std::net::IpAddr;

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, RuleKey};
use firew_sys::{ManagedMarker, ManagedNamespace};

use super::{BrokenIptablesRecord, IptablesRecord};

pub(crate) struct EnumeratedIptables {
    pub(crate) rules: HashMap<RuleKey, IptablesRecord>,
    pub(crate) broken_records: HashMap<RuleKey, BrokenIptablesRecord>,
    pub(crate) orphan_rows: Vec<(String, String)>,
    pub(crate) drifted: Vec<String>,
}

#[derive(Clone, Debug)]
pub(super) struct ParsedRow {
    pub(super) marker: ManagedMarker,
    pub(super) chain: String,
    pub(super) spec: String,
    pub(super) action: Action,
    pub(super) direction: Direction,
    pub(super) protocol: Protocol,
    pub(super) remote_address: Option<ipnet::IpNet>,
    pub(super) local_address: Option<ipnet::IpNet>,
    pub(super) remote_port: Option<PortRange>,
    pub(super) local_port: Option<PortRange>,
    pub(super) remote_set: Option<String>,
}

firew_sys::impl_native_row!(ParsedRow, remote_set = remote_set);

struct ParsedMatchers {
    protocol: Protocol,
    source_address: Option<ipnet::IpNet>,
    destination_address: Option<ipnet::IpNet>,
    source_port: Option<PortRange>,
    destination_port: Option<PortRange>,
    action: Option<Action>,
    remote_set: Option<String>,
    /// The `src` or `dst` flag after the set name: which packet address the
    /// set is matched against.
    remote_set_selector: Option<String>,
}

pub(super) fn try_extract_key_from_spec(
    spec: &str,
    namespace: &ManagedNamespace,
) -> Option<RuleKey> {
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let idx = tokens.iter().position(|t| *t == "--comment")?;
    let val = tokens.get(idx + 1)?.trim_matches('"');
    ManagedMarker::parse(val, namespace).ok().map(|m| m.key)
}

fn parse_spec_tokens(tokens: &[&str], key: &RuleKey) -> Result<ParsedMatchers, Error> {
    let mut protocol = Protocol::Any;
    let mut source_address = None;
    let mut destination_address = None;
    let mut source_port = None;
    let mut destination_port = None;
    let mut action = None;
    let mut remote_set = None;
    let mut remote_set_selector = None;
    let mut index = 0;
    while index < tokens.len() {
        let value = tokens.get(index + 1).copied();
        let mut step = 2;
        match tokens[index] {
            "-s" => source_address = Some(parse_address(value, key)?),
            "-d" => destination_address = Some(parse_address(value, key)?),
            "-p" => protocol = parse_protocol(value, key)?,
            "--sport" => source_port = Some(parse_native_port(value, key)?),
            "--dport" => destination_port = Some(parse_native_port(value, key)?),
            "-j" => action = Some(parse_action(value, key)?),
            "-m" if matches!(value, Some("comment" | "tcp" | "udp" | "set" | "icmp")) => {}
            "--match-set" => {
                remote_set = Some(
                    value
                        .ok_or_else(|| {
                            Error::new(
                                ErrorKind::CorruptNativeState,
                                "managed iptables row has --match-set with no set name",
                            )
                            .with_logical_key(key)
                        })?
                        .to_owned(),
                );
                remote_set_selector = tokens.get(index + 2).map(|flag| (*flag).to_owned());
                step = 3;
            }
            "--comment" => {}
            "--reject-with" if matches!(value, Some("icmp-port-unreachable")) => {}
            unknown => {
                return Err(Error::new(
                    ErrorKind::CorruptNativeState,
                    format!("unsupported token {unknown} in managed iptables row"),
                )
                .with_logical_key(key))
            }
        }
        index += step;
    }

    Ok(ParsedMatchers {
        protocol,
        source_address,
        destination_address,
        source_port,
        destination_port,
        action,
        remote_set,
        remote_set_selector,
    })
}

pub(super) fn parse_native_row(
    line: &str,
    chain: &str,
    inbound: bool,
    namespace: &firew_sys::ManagedNamespace,
) -> Result<ParsedRow, Error> {
    let prefix = format!("-A {chain} ");
    let spec = line.strip_prefix(&prefix).ok_or_else(|| {
        Error::new(
            ErrorKind::CorruptNativeState,
            "managed iptables row has an unexpected chain grammar",
        )
    })?;
    let tokens: Vec<&str> = spec.split_whitespace().collect();
    let marker_index = tokens
        .iter()
        .position(|token| *token == "--comment")
        .ok_or_else(|| {
            Error::new(
                ErrorKind::CorruptNativeState,
                "managed iptables row has no marker",
            )
        })?;
    let marker_value = tokens
        .get(marker_index + 1)
        .map(|value| value.trim_matches('"'))
        .ok_or_else(|| {
            Error::new(
                ErrorKind::CorruptNativeState,
                "managed iptables marker has no value",
            )
        })?;
    let marker = ManagedMarker::parse(marker_value, namespace)?;
    let key = &marker.key;

    let matchers = parse_spec_tokens(&tokens, key)?;
    let ParsedMatchers {
        protocol,
        source_address,
        destination_address,
        source_port,
        destination_port,
        action,
        remote_set,
        remote_set_selector,
    } = matchers;
    // A set holds remote addresses: the source of an inbound packet and the
    // destination of an outbound one. Matched against the other end, the
    // row filters the local host's own address instead.
    let remote_end = if inbound { "src" } else { "dst" };
    if remote_set.is_some() && remote_set_selector.as_deref() != Some(remote_end) {
        return Err(Error::new(
            ErrorKind::CorruptNativeState,
            format!("managed iptables set match must select {remote_end} in this chain"),
        )
        .with_logical_key(key));
    }
    let action = action.ok_or_else(|| {
        Error::new(
            ErrorKind::CorruptNativeState,
            "managed iptables row has no action",
        )
        .with_logical_key(key)
    })?;
    let (remote_address, local_address, remote_port, local_port, direction) = if inbound {
        (
            source_address,
            destination_address,
            source_port,
            destination_port,
            Direction::Inbound,
        )
    } else {
        (
            destination_address,
            source_address,
            destination_port,
            source_port,
            Direction::Outbound,
        )
    };
    Ok(ParsedRow {
        marker,
        chain: chain.to_owned(),
        spec: spec.to_owned(),
        action,
        direction,
        protocol,
        remote_address,
        local_address,
        remote_port,
        local_port,
        remote_set,
    })
}

pub(super) fn parse_address(value: Option<&str>, key: &RuleKey) -> Result<ipnet::IpNet, Error> {
    let raw = value.unwrap_or_default();
    if let Ok(net) = raw.parse::<ipnet::IpNet>() {
        return Ok(net.trunc());
    }
    raw.parse::<IpAddr>()
        .map(ipnet::IpNet::from)
        .map_err(|source| native_parse_error(key, "address", source))
}

fn parse_native_port(value: Option<&str>, key: &RuleKey) -> Result<PortRange, Error> {
    let value = value.unwrap_or_default();
    let result = if let Some((start, end)) = value.split_once(':') {
        PortRange::range(parse_u16(start, key)?, parse_u16(end, key)?)
    } else {
        PortRange::single(parse_u16(value, key)?)
    };
    result.map_err(|error| {
        Error::new(
            ErrorKind::CorruptNativeState,
            format!("invalid managed iptables port: {error}"),
        )
        .with_logical_key(key)
    })
}

fn parse_u16(value: &str, key: &RuleKey) -> Result<u16, Error> {
    value
        .parse()
        .map_err(|source| native_parse_error(key, "port", source))
}

pub(crate) fn parse_protocol(value: Option<&str>, key: &RuleKey) -> Result<Protocol, Error> {
    let raw = value.unwrap_or_default();
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "all" | "0" => return Ok(Protocol::Any),
        "tcp" | "6" => return Ok(Protocol::Tcp),
        "udp" | "17" => return Ok(Protocol::Udp),
        "icmp" | "1" => return Ok(Protocol::IcmpV4),
        "ipv6-icmp" | "icmpv6" | "58" => return Ok(Protocol::IcmpV6),
        _ => {}
    }
    if let Ok(num) = lower.parse::<u8>() {
        return Ok(Protocol::Other(num).canonicalize());
    }
    if let Some(num) = lookup_protocol_name(&lower) {
        return Ok(Protocol::Other(num).canonicalize());
    }
    Err(Error::new(
        ErrorKind::CorruptNativeState,
        format!("managed iptables row has an unknown protocol {raw}"),
    )
    .with_logical_key(key))
}

fn lookup_protocol_name(lower_name: &str) -> Option<u8> {
    static IANA_PROTOCOLS: &[(&str, u8)] = &[
        ("icmp", 1),
        ("igmp", 2),
        ("ggp", 3),
        ("ipencap", 4),
        ("ipv4", 4),
        ("st", 5),
        ("tcp", 6),
        ("egp", 8),
        ("igp", 9),
        ("pup", 12),
        ("udp", 17),
        ("hmp", 20),
        ("xns-idp", 22),
        ("rdp", 27),
        ("iso-tp4", 29),
        ("dccp", 33),
        ("xtp", 36),
        ("ddp", 37),
        ("idpr-cmtp", 38),
        ("ipv6", 41),
        ("ipv6-route", 43),
        ("ipv6-frag", 44),
        ("idrp", 45),
        ("rsvp", 46),
        ("gre", 47),
        ("esp", 50),
        ("ah", 51),
        ("skip", 57),
        ("ipv6-icmp", 58),
        ("icmpv6", 58),
        ("ipv6-nonxt", 59),
        ("ipv6-opts", 60),
        ("rspf", 73),
        ("vmtp", 81),
        ("eigrp", 88),
        ("ospf", 89),
        ("ospfigp", 89),
        ("ax.25", 93),
        ("ipip", 94),
        ("etherip", 97),
        ("encap", 98),
        ("pim", 103),
        ("ipcomp", 108),
        ("vrrp", 112),
        ("l2tp", 115),
        ("isis", 124),
        ("sctp", 132),
        ("fc", 133),
        ("mobility-header", 135),
        ("udplite", 136),
        ("mpls-in-ip", 137),
        ("manet", 138),
        ("hip", 139),
        ("shim6", 140),
        ("wesp", 141),
        ("rohc", 142),
    ];

    if let Some(&(_, num)) = IANA_PROTOCOLS.iter().find(|&&(name, _)| name == lower_name) {
        return Some(num);
    }

    if let Ok(contents) = std::fs::read_to_string("/etc/protocols") {
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(canon) = parts.next() else {
                continue;
            };
            let Some(num_str) = parts.next() else {
                continue;
            };
            let Ok(num) = num_str.parse::<u8>() else {
                continue;
            };
            if canon.eq_ignore_ascii_case(lower_name)
                || parts.any(|alias| alias.eq_ignore_ascii_case(lower_name))
            {
                return Some(num);
            }
        }
    }
    None
}

fn parse_action(value: Option<&str>, key: &RuleKey) -> Result<Action, Error> {
    match value.unwrap_or_default() {
        "ACCEPT" => Ok(Action::Allow),
        "DROP" => Ok(Action::Block),
        "REJECT" => Ok(Action::Reject),
        _ => Err(Error::new(
            ErrorKind::CorruptNativeState,
            "managed iptables row has an invalid action",
        )
        .with_logical_key(key)),
    }
}

fn native_parse_error(
    key: &RuleKey,
    field: &str,
    source: impl std::error::Error + Send + Sync + 'static,
) -> Error {
    Error::new(
        ErrorKind::CorruptNativeState,
        format!("managed iptables row has an invalid {field}"),
    )
    .with_logical_key(key)
    .with_source(source)
}

pub(super) fn reconstruct_record<F>(
    key: RuleKey,
    mut rows: Vec<ParsedRow>,
    load_set: &F,
) -> Result<(RuleKey, IptablesRecord), Error>
where
    F: Fn(&str) -> Result<Option<Vec<ipnet::IpNet>>, Error>,
{
    let rule = firew_sys::rebuild_rule(&key, &mut rows, |rows| {
        rows[0]
            .remote_set
            .as_deref()
            .map(|name| load_set(name).map(Option::unwrap_or_default))
            .transpose()
    })?;
    let set_name = rows[0].remote_set.clone();
    let native_rows = rows.into_iter().map(|row| (row.chain, row.spec)).collect();
    Ok((
        key,
        IptablesRecord {
            rule,
            rows: native_rows,
            set_name,
        },
    ))
}
