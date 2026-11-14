//! Translating rules into nftables statements, sets, and batch entries.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use firew_core::{
    Action, AddressSetMode, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey,
};
use firew_sys::{address_pairs, alternatives, PartMarkers};
use ipnet::IpNet;
use nftables::batch::Batch;
use nftables::expr::{Expression, Meta, MetaKey, NamedExpression, Payload, PayloadField, Prefix};
use nftables::schema::{NfListObject, Rule as NftRule, Set, SetFlag, SetType, SetTypeValue};
use nftables::stmt::{Match, Operator, Statement};

use super::{NftHandle, NftablesBackend, RuleVariant, SetInstall, FAMILY, TABLE_NAME};

impl NftablesBackend {
    pub(crate) fn build_statements(
        rule: &Rule,
        inbound: bool,
        remote_address: Option<&IpNet>,
        local_address: Option<&IpNet>,
        remote_port: Option<&PortRange>,
        local_port: Option<&PortRange>,
    ) -> Vec<Statement<'static>> {
        let mut statements = Vec::with_capacity(8);

        if let Some(net) = remote_address {
            statements.push(address_match(net, inbound, false));
        }
        if let Some(net) = local_address {
            statements.push(address_match(net, inbound, true));
        }

        if remote_address.is_none() && local_address.is_none() {
            match rule.protocol() {
                Protocol::IcmpV4 => {
                    statements.push(Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Nfproto,
                        })),
                        right: Expression::String(Cow::Borrowed("ipv4")),
                        op: Operator::EQ,
                    }));
                }
                Protocol::IcmpV6 => {
                    statements.push(Statement::Match(Match {
                        left: Expression::Named(NamedExpression::Meta(Meta {
                            key: MetaKey::Nfproto,
                        })),
                        right: Expression::String(Cow::Borrowed("ipv6")),
                        op: Operator::EQ,
                    }));
                }
                _ => {}
            }
        }

        if let Some(proto) = rule.protocol().number() {
            statements.push(Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::Number(u32::from(proto)),
                op: Operator::EQ,
            }));
        }

        if let Some(port) = remote_port {
            statements.extend(port_matches(*port, rule.protocol(), inbound, false));
        }
        if let Some(port) = local_port {
            statements.extend(port_matches(*port, rule.protocol(), inbound, true));
        }

        match rule.action() {
            Action::Allow => statements.push(Statement::Accept(None)),
            Action::Block => statements.push(Statement::Drop(None)),
            Action::Reject => statements.push(Statement::Reject(None)),
        }

        statements
    }

    fn build_nft_rule(
        rule: &Rule,
        chain_name: &str,
        variant: RuleVariant<'_>,
        marker: String,
    ) -> Result<NftRule<'static>, Error> {
        firew_sys::reject_unresolved_domains(rule)?;
        if rule.application_path().is_some() {
            return Err(Error::new(
                ErrorKind::UnsupportedMatcher,
                "application-only rules require cgroup integration on linux",
            )
            .with_logical_key(rule.logical_key()));
        }

        let expr = Self::build_statements(
            rule,
            variant.inbound,
            variant.remote_address,
            variant.local_address,
            variant.remote_port,
            variant.local_port,
        );
        Ok(managed_rule(chain_name, expr, marker))
    }

    /// This namespace's chain for one direction.
    fn chain(&self, inbound: bool) -> &str {
        if inbound {
            &self.in_chain
        } else {
            &self.out_chain
        }
    }

    fn chains_for_direction(direction: Direction) -> &'static [bool] {
        match direction {
            Direction::Outbound => &[false],
            Direction::Inbound => &[true],
            Direction::Both => &[false, true],
        }
    }

    /// Builds the named sets and referencing rules for an address-set rule.
    ///
    /// Preserves OR semantics within `local_addresses`, `remote_ports`, and
    /// `local_ports`, and AND semantics across populated fields.
    pub(crate) fn build_set_objects(&self, rule: &Rule) -> Result<SetInstall, Error> {
        let key = rule.logical_key();
        let directions = Self::chains_for_direction(rule.direction());
        let remote_ports = alternatives(rule.remote_ports());
        let local_ports = alternatives(rule.local_ports());
        let plans = family_plans(rule);

        let total_rows: usize = plans
            .iter()
            .map(|plan| {
                directions.len() * plan.local_alts.len() * remote_ports.len() * local_ports.len()
            })
            .sum();
        let namespace = self.config.managed_namespace();
        let mut markers = PartMarkers::new("nftables", key, &namespace, total_rows)?;
        let mut install = SetInstall {
            sets: Vec::with_capacity(plans.len()),
            rules: Vec::with_capacity(total_rows),
            set_names: Vec::with_capacity(plans.len()),
        };

        for plan in &plans {
            let set_name = set_name_for(&namespace, key, plan.is_v4);
            install
                .sets
                .push(set_object(&set_name, plan.is_v4, Some(&plan.nets)));
            for &inbound in directions {
                for &local_address in &plan.local_alts {
                    for &remote_port in &remote_ports {
                        for &local_port in &local_ports {
                            let expr = Self::build_set_statements(
                                rule,
                                inbound,
                                plan.is_v4,
                                &set_name,
                                local_address,
                                remote_port,
                                local_port,
                            );
                            let marker = markers.encode_next()?;
                            install
                                .rules
                                .push(managed_rule(self.chain(inbound), expr, marker));
                        }
                    }
                }
            }
            install.set_names.push(set_name);
        }
        Ok(install)
    }

    pub(crate) fn build_cartesian_rules(
        &self,
        rule: &Rule,
    ) -> Result<Vec<NftRule<'static>>, Error> {
        let key = rule.logical_key().clone();
        let directions = Self::chains_for_direction(rule.direction());
        let remote_ports = alternatives(rule.remote_ports());
        let local_ports = alternatives(rule.local_ports());

        let address_pairs = address_pairs(rule);

        let total_rows =
            directions.len() * address_pairs.len() * remote_ports.len() * local_ports.len();
        let namespace = self.config.managed_namespace();
        let mut markers = PartMarkers::new("nftables", &key, &namespace, total_rows)?;
        let mut out = Vec::with_capacity(total_rows);

        for &inbound in directions {
            for &(remote_address, local_address) in &address_pairs {
                for &remote_port in &remote_ports {
                    for &local_port in &local_ports {
                        let variant = RuleVariant {
                            inbound,
                            remote_address,
                            local_address,
                            remote_port,
                            local_port,
                        };
                        let marker = markers.encode_next()?;
                        out.push(Self::build_nft_rule(
                            rule,
                            self.chain(inbound),
                            variant,
                            marker,
                        )?);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Statements for a rule whose remote addresses live in a named set.
    pub(crate) fn build_set_statements(
        rule: &Rule,
        inbound: bool,
        is_v4: bool,
        set_name: &str,
        local_address: Option<&IpNet>,
        remote_port: Option<&PortRange>,
        local_port: Option<&PortRange>,
    ) -> Vec<Statement<'static>> {
        let mut statements = Vec::with_capacity(8);
        let protocol = if is_v4 { "ip" } else { "ip6" };
        let field = if inbound { "saddr" } else { "daddr" };
        statements.push(Statement::Match(Match {
            left: payload_field(protocol, field),
            right: Expression::String(Cow::Owned(format!("@{set_name}"))),
            op: Operator::EQ,
        }));

        if let Some(local_net) = local_address {
            statements.push(address_match(local_net, inbound, true));
        }

        if let Some(proto) = rule.protocol().number() {
            statements.push(Statement::Match(Match {
                left: Expression::Named(NamedExpression::Meta(Meta {
                    key: MetaKey::L4proto,
                })),
                right: Expression::Number(u32::from(proto)),
                op: Operator::EQ,
            }));
        }
        if let Some(port) = remote_port {
            statements.extend(port_matches(*port, rule.protocol(), inbound, false));
        }
        if let Some(port) = local_port {
            statements.extend(port_matches(*port, rule.protocol(), inbound, true));
        }

        match rule.action() {
            Action::Allow => statements.push(Statement::Accept(None)),
            Action::Block => statements.push(Statement::Drop(None)),
            Action::Reject => statements.push(Statement::Reject(None)),
        }
        statements
    }

    pub(super) fn append_rule_install_to_batch(
        &self,
        batch: &mut Batch<'static>,
        rule: &Rule,
    ) -> Result<Vec<String>, Error> {
        if rule.address_set_mode() == AddressSetMode::Set {
            let install = self.build_set_objects(rule)?;
            for set in install.sets {
                batch.add(NfListObject::Set(Box::new(set)));
            }
            for nft_rule in install.rules {
                batch.add(NfListObject::Rule(nft_rule));
            }
            Ok(install.set_names)
        } else {
            let nft_rules = self.build_cartesian_rules(rule)?;
            for nft_rule in nft_rules {
                batch.add(NfListObject::Rule(nft_rule));
            }
            Ok(Vec::new())
        }
    }

    pub(super) fn append_record_deletion_to_batch(
        batch: &mut Batch<'static>,
        handles: &[NftHandle],
        sets: &[String],
    ) {
        for nft_handle in handles {
            batch.delete(NfListObject::Rule(NftRule {
                family: FAMILY,
                table: Cow::Borrowed(TABLE_NAME),
                chain: Cow::Owned(nft_handle.chain.clone()),
                handle: Some(nft_handle.handle),
                ..Default::default()
            }));
        }
        for set_name in sets {
            // A delete names the set; its type and elements do not matter.
            batch.delete(NfListObject::Set(Box::new(set_object(
                set_name, true, None,
            ))));
        }
    }
}
/// One address family's share of a set-mode rule: its remote set and the
/// local addresses of the same family it pairs with.
struct FamilyPlan<'a> {
    is_v4: bool,
    nets: Vec<IpNet>,
    local_alts: Vec<Option<&'a IpNet>>,
}

/// Splits a set-mode rule by address family, pairing each family's remote set
/// only with compatible local addresses. A family with no compatible local
/// address is dropped.
fn family_plans(rule: &Rule) -> Vec<FamilyPlan<'_>> {
    let (v4, v6): (Vec<IpNet>, Vec<IpNet>) = rule
        .remote_addresses()
        .iter()
        .partition(|net| net.addr().is_ipv4());
    let mut plans = Vec::new();
    for (is_v4, nets) in [(true, v4), (false, v6)] {
        if nets.is_empty() {
            continue;
        }
        let local_alts: Vec<Option<&IpNet>> = if rule.local_addresses().is_empty() {
            vec![None]
        } else {
            rule.local_addresses()
                .iter()
                .filter(|local| local.addr().is_ipv4() == is_v4)
                .map(Some)
                .collect()
        };
        if local_alts.is_empty() {
            continue;
        }
        // A set-mode rule's addresses are already canonical: truncated, sorted,
        // and with nested networks collapsed into the outer one, which an
        // interval set requires. Neighbours are not merged, so the kernel lists
        // back exactly the rule that was installed.
        plans.push(FamilyPlan {
            is_v4,
            nets,
            local_alts,
        });
    }
    plans
}

/// A named set in the `firew_rs` table. With `nets` it is the interval set to
/// install; without, a reference by name, as a delete needs.
pub(super) fn set_object(name: &str, is_v4: bool, nets: Option<&[IpNet]>) -> Set<'static> {
    Set {
        family: FAMILY,
        table: Cow::Borrowed(TABLE_NAME),
        name: Cow::Owned(name.to_owned()),
        handle: None,
        set_type: SetTypeValue::Single(if is_v4 {
            SetType::Ipv4Addr
        } else {
            SetType::Ipv6Addr
        }),
        policy: None,
        flags: nets.map(|_| HashSet::from([SetFlag::Interval])),
        elem: nets.map(|nets| Cow::Owned(nets.iter().map(ip_expression).collect())),
        timeout: None,
        gc_interval: None,
        size: None,
        comment: None,
    }
}

/// A managed rule in `chain`, carrying its ownership marker as the comment.
pub(super) fn managed_rule(
    chain: &str,
    expr: Vec<Statement<'static>>,
    marker: String,
) -> NftRule<'static> {
    NftRule {
        family: FAMILY,
        table: Cow::Borrowed(TABLE_NAME),
        chain: Cow::Owned(chain.to_owned()),
        expr: Cow::Owned(expr),
        comment: Some(Cow::Owned(marker)),
        ..Default::default()
    }
}

/// The combined entries of the sets a rule's rows reference: `None` for rows
/// without sets, and an empty list when any set is missing or empty.
pub(super) fn set_entries(
    sets: &[String],
    set_elements: &HashMap<String, Vec<IpNet>>,
) -> Option<Vec<IpNet>> {
    if sets.is_empty() {
        return None;
    }
    let mut combined = Vec::new();
    for set_name in sets {
        match set_elements.get(set_name) {
            Some(nets) if !nets.is_empty() => combined.extend(nets.iter().copied()),
            _ => return Some(Vec::new()),
        }
    }
    Some(combined)
}

/// Derives an nftables set name from a rule key and address family.
fn set_name_for(namespace: &firew_sys::ManagedNamespace, key: &RuleKey, is_v4: bool) -> String {
    let token = namespace.native_object_token(key);
    let suffix = if is_v4 { "v4" } else { "v6" };
    format!("fw_{token}_{suffix}")
}

fn payload_field(protocol: &str, field: &str) -> Expression<'static> {
    Expression::Named(NamedExpression::Payload(Payload::PayloadField(
        PayloadField {
            protocol: Cow::Owned(protocol.to_owned()),
            field: Cow::Owned(field.to_owned()),
        },
    )))
}

fn address_match(net: &IpNet, inbound: bool, local: bool) -> Statement<'static> {
    let source = inbound != local;
    let (protocol, field) = if net.addr().is_ipv4() {
        if source {
            ("ip", "saddr")
        } else {
            ("ip", "daddr")
        }
    } else if source {
        ("ip6", "saddr")
    } else {
        ("ip6", "daddr")
    };

    Statement::Match(Match {
        left: payload_field(protocol, field),
        right: ip_expression(net),
        op: Operator::EQ,
    })
}

fn port_matches(
    port: PortRange,
    protocol: Protocol,
    inbound: bool,
    local: bool,
) -> Vec<Statement<'static>> {
    let protocol = if protocol == Protocol::Udp {
        "udp"
    } else {
        "tcp"
    };
    let source = inbound != local;
    let field = if source { "sport" } else { "dport" };
    let left = payload_field(protocol, field);
    if port.is_single() {
        vec![Statement::Match(Match {
            left,
            right: Expression::Number(u32::from(port.start())),
            op: Operator::EQ,
        })]
    } else {
        vec![
            Statement::Match(Match {
                left: left.clone(),
                right: Expression::Number(u32::from(port.start())),
                op: Operator::GEQ,
            }),
            Statement::Match(Match {
                left,
                right: Expression::Number(u32::from(port.end())),
                op: Operator::LEQ,
            }),
        ]
    }
}

pub(crate) fn ip_expression(net: &IpNet) -> Expression<'static> {
    let network = net.network();
    let max_prefix = if network.is_ipv4() { 32 } else { 128 };
    if net.prefix_len() == max_prefix {
        Expression::String(Cow::Owned(network.to_string()))
    } else {
        Expression::Named(NamedExpression::Prefix(Prefix {
            addr: Box::new(Expression::String(Cow::Owned(network.to_string()))),
            len: u32::from(net.prefix_len()),
        }))
    }
}
