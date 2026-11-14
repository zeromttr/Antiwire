//! Rebuilding rules from an nftables listing.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, RuleKey};
use firew_sys::{parse_native_net, ManagedMarker, ManagedNamespace};
use ipnet::IpNet;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload};
use nftables::schema::{NfListObject, NfObject, Nftables, Rule as NftRule};
use nftables::stmt::{Match, Operator, Statement};

use super::build::set_entries;
use super::{NftHandle, RuleRecord, TABLE_NAME};

pub(super) struct ReconstructedNftables {
    pub(super) rules: HashMap<RuleKey, RuleRecord>,
    pub(super) orphan_handles: HashMap<RuleKey, Vec<NftHandle>>,
    pub(super) orphan_sets: HashMap<RuleKey, Vec<String>>,
    pub(super) unkeyed_orphans: Vec<NftHandle>,
    pub(super) drifted: Vec<String>,
}

struct ParsedNftRow {
    marker: ManagedMarker,
    chain: String,
    handle: u32,
    action: Action,
    direction: Direction,
    protocol: Protocol,
    remote_address: Option<IpNet>,
    local_address: Option<IpNet>,
    remote_port: Option<PortRange>,
    local_port: Option<PortRange>,
    remote_set: Option<String>,
}

firew_sys::impl_native_row!(ParsedNftRow, remote_set = remote_set);

/// Fails when a listed rule in the `firew_rs` table carries no handle.
pub(super) fn ensure_rule_handles(ruleset: &Nftables<'_>) -> Result<(), Error> {
    let missing = ruleset.objects.iter().any(|obj| {
        matches!(
            obj,
            NfObject::ListObject(NfListObject::Rule(rule))
                if rule.table == TABLE_NAME && rule.handle.is_none()
        )
    });
    if missing {
        return Err(Error::new(
            ErrorKind::CorruptNativeState,
            "nft listed a firew_rs rule without its handle; rules cannot be deleted safely",
        ));
    }
    Ok(())
}

pub(super) fn reconstruct_from_ruleset(
    ruleset: &Nftables<'_>,
    namespace: &ManagedNamespace,
    in_chain: &str,
    out_chain: &str,
) -> ReconstructedNftables {
    let mut set_elements: HashMap<String, Vec<IpNet>> = HashMap::new();
    for obj in ruleset.objects.iter() {
        let NfObject::ListObject(NfListObject::Set(set)) = obj else {
            continue;
        };
        if set.table != TABLE_NAME {
            continue;
        }
        let mut nets = Vec::new();
        if let Some(elems) = &set.elem {
            for expr in elems.iter() {
                if let Some(net) = parse_ip_expression(expr) {
                    nets.push(net.trunc());
                }
            }
        }
        set_elements.insert(set.name.to_string(), nets);
    }

    let mut grouped: BTreeMap<RuleKey, Vec<ParsedNftRow>> = BTreeMap::new();
    let mut orphan_handles: HashMap<RuleKey, Vec<NftHandle>> = HashMap::new();
    let mut orphan_sets: HashMap<RuleKey, Vec<String>> = HashMap::new();
    let mut unkeyed_orphans: Vec<NftHandle> = Vec::new();
    let mut drifted: Vec<String> = Vec::new();

    for obj in ruleset.objects.iter() {
        let NfObject::ListObject(NfListObject::Rule(rule)) = obj else {
            continue;
        };
        if rule.table != TABLE_NAME || (rule.chain != in_chain && rule.chain != out_chain) {
            continue;
        }
        let inbound = rule.chain == in_chain;
        // `list_table` refuses listings without handles; a fixture without one
        // gets an impossible handle rather than a real one's number.
        let handle = rule.handle.unwrap_or(0);
        let nft_handle = NftHandle {
            chain: rule.chain.to_string(),
            handle,
        };
        let Some(comment) = rule.comment.as_deref() else {
            unkeyed_orphans.push(nft_handle);
            drifted.push(format!("{}:{handle}", rule.chain));
            continue;
        };
        let Ok(marker) = ManagedMarker::parse(comment, namespace) else {
            unkeyed_orphans.push(nft_handle);
            drifted.push(comment.to_owned());
            continue;
        };
        let Some(parsed) = parse_nft_rule_statements(rule, inbound, marker.clone()) else {
            orphan_handles
                .entry(marker.key)
                .or_default()
                .push(nft_handle);
            drifted.push(comment.to_owned());
            continue;
        };
        grouped.entry(marker.key).or_default().push(parsed);
    }

    let mut rules = HashMap::with_capacity(grouped.len());
    for (key, mut rows) in grouped {
        let handles: Vec<NftHandle> = rows
            .iter()
            .map(|r| NftHandle {
                chain: r.chain.clone(),
                handle: r.handle,
            })
            .collect();
        let mut sets: Vec<String> = rows.iter().filter_map(|r| r.remote_set.clone()).collect();
        sets.sort();
        sets.dedup();

        let rebuilt =
            firew_sys::rebuild_rule(&key, &mut rows, |_| Ok(set_entries(&sets, &set_elements)));
        if let Ok(rule) = rebuilt {
            rules.insert(
                key,
                RuleRecord {
                    rule,
                    handles,
                    sets,
                    dirty: false,
                },
            );
        } else {
            drifted.push(key.to_string());
            orphan_handles
                .entry(key.clone())
                .or_default()
                .extend(handles);
            orphan_sets.entry(key).or_default().extend(sets);
        }
    }

    ReconstructedNftables {
        rules,
        orphan_handles,
        orphan_sets,
        unkeyed_orphans,
        drifted,
    }
}

fn parse_nft_rule_statements(
    nft_rule: &NftRule<'_>,
    inbound: bool,
    marker: ManagedMarker,
) -> Option<ParsedNftRow> {
    let mut scan = ScannedRule::new();
    for stmt in nft_rule.expr.iter() {
        match stmt {
            Statement::Accept(_) => scan.action = Some(Action::Allow),
            Statement::Drop(_) => scan.action = Some(Action::Block),
            Statement::Reject(_) => scan.action = Some(Action::Reject),
            Statement::Match(m) => scan.matched(m, &marker.key)?,
            _ => return None,
        }
    }
    scan.into_row(nft_rule, inbound, marker)
}

/// Bounds collected from one port field's `==`, `>=`, and `<=` matches.
#[derive(Default)]
struct PortBounds {
    low: Option<u16>,
    high: Option<u16>,
}

impl PortBounds {
    fn apply(&mut self, op: Operator, value: u16) -> Option<()> {
        match op {
            Operator::EQ => (self.low, self.high) = (Some(value), Some(value)),
            Operator::GEQ => self.low = Some(value),
            Operator::LEQ => self.high = Some(value),
            _ => return None,
        }
        Some(())
    }

    /// The matched range, `None` when the field was not matched. Only one
    /// bound, which no managed rule produces, is an error.
    fn range(self) -> Result<Option<PortRange>, ()> {
        match (self.low, self.high) {
            (Some(low), Some(high)) => PortRange::range(low, high).map(Some).map_err(|_| ()),
            (None, None) => Ok(None),
            _ => Err(()),
        }
    }
}

/// Matchers collected while walking one listed rule's statements. Any
/// statement a managed rule never contains makes the scan fail with `None`.
struct ScannedRule {
    action: Option<Action>,
    protocol: Protocol,
    source_address: Option<IpNet>,
    dest_address: Option<IpNet>,
    remote_set: Option<String>,
    source_port: PortBounds,
    dest_port: PortBounds,
}

impl ScannedRule {
    fn new() -> Self {
        Self {
            action: None,
            protocol: Protocol::Any,
            source_address: None,
            dest_address: None,
            remote_set: None,
            source_port: PortBounds::default(),
            dest_port: PortBounds::default(),
        }
    }

    /// Managed rules test equality, and bound port ranges with `>=` and `<=`.
    /// Any other operator, such as `!=`, inverts or changes what a match
    /// selects, so the scan refuses it.
    fn matched(&mut self, m: &Match<'_>, key: &RuleKey) -> Option<()> {
        match &m.left {
            Expression::Named(NamedExpression::Meta(meta)) if m.op == Operator::EQ => {
                self.meta(meta, &m.right, key)
            }
            Expression::Named(NamedExpression::Payload(Payload::PayloadField(field))) => {
                self.payload(field.protocol.as_ref(), field.field.as_ref(), m)
            }
            _ => None,
        }
    }

    fn meta(&mut self, meta: &Meta, right: &Expression<'_>, key: &RuleKey) -> Option<()> {
        match meta.key {
            MetaKey::L4proto => {
                // `nft -j list` prints protocol names (`"tcp"`). Adds use the
                // numeric id. Both have to round-trip to the same `Protocol`.
                self.protocol = match right {
                    Expression::Number(n) => Protocol::Other(u8::try_from(*n).ok()?).canonicalize(),
                    Expression::String(name) => {
                        crate::iptables::parse_protocol(Some(name.trim()), key).ok()?
                    }
                    _ => return None,
                };
                Some(())
            }
            // The family constraint on address-less ICMP rules says nothing the
            // protocol does not already.
            MetaKey::Nfproto => Some(()),
            _ => None,
        }
    }

    fn payload(&mut self, protocol: &str, field: &str, m: &Match<'_>) -> Option<()> {
        match (protocol, field) {
            ("ip" | "ip6", "saddr" | "daddr") => {
                if m.op != Operator::EQ {
                    return None;
                }
                if let Expression::String(text) = &m.right {
                    if let Some(set_name) = text.strip_prefix('@') {
                        self.remote_set = Some(set_name.to_owned());
                        return Some(());
                    }
                }
                let net = parse_ip_expression(&m.right)?;
                if field == "saddr" {
                    self.source_address = Some(net);
                } else {
                    self.dest_address = Some(net);
                }
                Some(())
            }
            ("tcp" | "udp", "sport" | "dport") => {
                if self.protocol == Protocol::Any {
                    self.protocol = if protocol == "udp" {
                        Protocol::Udp
                    } else {
                        Protocol::Tcp
                    };
                }
                let Expression::Number(n) = &m.right else {
                    return None;
                };
                let bounds = if field == "sport" {
                    &mut self.source_port
                } else {
                    &mut self.dest_port
                };
                bounds.apply(m.op, u16::try_from(*n).ok()?)
            }
            _ => None,
        }
    }

    /// Maps source and destination onto remote and local for the chain's direction.
    fn into_row(
        self,
        nft_rule: &NftRule<'_>,
        inbound: bool,
        marker: ManagedMarker,
    ) -> Option<ParsedNftRow> {
        let action = self.action?;
        let source_port = self.source_port.range().ok()?;
        let dest_port = self.dest_port.range().ok()?;
        let (remote_address, local_address, remote_port, local_port, direction) = if inbound {
            (
                self.source_address,
                self.dest_address,
                source_port,
                dest_port,
                Direction::Inbound,
            )
        } else {
            (
                self.dest_address,
                self.source_address,
                dest_port,
                source_port,
                Direction::Outbound,
            )
        };
        Some(ParsedNftRow {
            marker,
            chain: nft_rule.chain.to_string(),
            handle: nft_rule.handle.unwrap_or(0),
            action,
            direction,
            protocol: self.protocol,
            remote_address,
            local_address,
            remote_port,
            local_port,
            remote_set: self.remote_set,
        })
    }
}

fn parse_ip_expression(expr: &Expression<'_>) -> Option<IpNet> {
    match expr {
        Expression::String(s) => parse_native_net(s),
        Expression::Named(NamedExpression::Prefix(prefix)) => {
            let Expression::String(addr_str) = prefix.addr.as_ref() else {
                return None;
            };
            let ip = addr_str.parse::<IpAddr>().ok()?;
            let len = u8::try_from(prefix.len).ok()?;
            IpNet::new(ip, len).ok().map(|n| n.trunc())
        }
        _ => None,
    }
}
