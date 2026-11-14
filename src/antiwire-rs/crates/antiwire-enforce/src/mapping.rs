use std::net::IpAddr;

use antiwire_policy::{EnforcementOp, RuleDirection, Verdict};
use firew_rs::AddressSetMode;

use crate::country::{plan_country_chunks, BackendCaps};
use firew_rs::{Action, Direction, PortRange, Protocol, Rule};
use ipnet::IpNet;

use crate::EnforceError;

/// Stable logical keys used to install and remove [`firew_rs::Rule`] rows.
pub(crate) fn op_rule_keys(op: &EnforcementOp) -> Result<Vec<String>, EnforceError> {
    match op {
        EnforcementOp::AddIpRule { rule_id, ip, .. }
        | EnforcementOp::RemoveIpRule { rule_id, ip, .. } => Ok(vec![ip_rule_key(*rule_id, ip)?]),
        EnforcementOp::AddDohBlock { doh_ips, port, .. } => doh_ips
            .iter()
            .flat_map(|ip| {
                [
                    doh_block_key(ip, *port, Protocol::Tcp),
                    doh_block_key(ip, *port, Protocol::Udp),
                ]
            })
            .collect(),
        EnforcementOp::RemoveDohBlocks => Ok(Vec::new()),
        EnforcementOp::AddAppRule { rule_id, .. }
        | EnforcementOp::RemoveAppRule { rule_id, .. } => Ok(vec![app_rule_key(*rule_id)]),
        EnforcementOp::RemoveDnsRule { rule_id, .. } => Ok(vec![dns_rule_key(*rule_id)]),
        // Country keys depend on how many chunks the backend needs, so the
        // filter tracks them per rule id rather than deriving them here.
        EnforcementOp::AddCountryBlock { .. } | EnforcementOp::RemoveCountryBlock { .. } => {
            Ok(Vec::new())
        }
    }
}

/// Expands one [`EnforcementOp`] into portable firewall rules.
pub(crate) fn apply_op(
    op: &EnforcementOp,
    caps: BackendCaps,
) -> Result<Vec<(String, Rule)>, EnforceError> {
    match op {
        EnforcementOp::AddIpRule {
            rule_id,
            ip,
            verdict,
            direction,
        } => {
            let key = ip_rule_key(*rule_id, ip)?;
            Ok(vec![(
                key,
                ip_policy_rule(*rule_id, ip, *verdict, *direction, caps)?,
            )])
        }
        EnforcementOp::AddAppRule {
            rule_id,
            app_path,
            verdict,
            direction,
        } => {
            let key = app_rule_key(*rule_id);
            Ok(vec![(
                key,
                app_policy_rule(*rule_id, app_path, *verdict, *direction)?,
            )])
        }
        EnforcementOp::AddDohBlock { doh_ips, port } => {
            let mut rules = Vec::with_capacity(doh_ips.len() * 2);
            for ip in doh_ips {
                for protocol in [Protocol::Tcp, Protocol::Udp] {
                    let key = doh_block_key(ip, *port, protocol)?;
                    rules.push((key, doh_block_rule(ip, *port, protocol)?));
                }
            }
            Ok(rules)
        }
        // Country blocks are expanded by `apply_country_op`, which needs the
        // backend's capabilities to decide how many rules to emit.
        EnforcementOp::AddCountryBlock { .. }
        | EnforcementOp::RemoveCountryBlock { .. }
        | EnforcementOp::RemoveIpRule { .. }
        | EnforcementOp::RemoveAppRule { .. }
        | EnforcementOp::RemoveDnsRule { .. }
        | EnforcementOp::RemoveDohBlocks => Ok(Vec::new()),
    }
}

/// Expands a country block into the rules the active backend can hold.
///
/// A set-capable backend usually yields one rule; others yield one per chunk of
/// networks.
pub(crate) fn apply_country_op(
    code: &str,
    networks: &[ipnet::IpNet],
    verdict: Verdict,
    direction: RuleDirection,
    caps: BackendCaps,
) -> Result<Vec<(String, Rule)>, EnforceError> {
    let chunks = plan_country_chunks(networks, caps);
    let total = chunks.len();
    let mut rules = Vec::with_capacity(total);
    for (index, chunk) in chunks.iter().enumerate() {
        let chunk_index = u16::try_from(index).map_err(|_| {
            EnforceError::InvalidOp(format!("country {code} needs more than 65535 rules"))
        })?;
        let key = country_block_key(code, chunk_index);
        rules.push((
            key.clone(),
            country_block_rule(
                &key,
                code,
                chunk,
                verdict,
                direction,
                caps,
                index + 1,
                total,
            )?,
        ));
    }
    Ok(rules)
}

/// Human-readable key for one part of a country block.
///
/// Deliberately readable rather than compact: the logical key is embedded in
/// the native rule name, so this is what someone sees when they open Windows
/// Firewall or run `nft list ruleset`. Numbering is 1-based to match the
/// "part N of M" wording in the description.
///
/// Example: `antiwire-us-rules-1`, `antiwire-us-rules-2`, ... — 19 characters
/// for a two-letter code, well inside the 32-byte key limit.
fn country_block_key(code: &str, chunk: u16) -> String {
    format!("{}{}", country_key_prefix(code), u32::from(chunk) + 1)
}

/// Shared prefix of every rule installed for one country.
///
/// Keyed by country code rather than database id so the name stays meaningful
/// and stable if the row is recreated.
#[must_use]
pub(crate) fn country_key_prefix(code: &str) -> String {
    format!(
        "{}-{}-rules-",
        crate::MANAGER_PREFIX,
        code.to_ascii_lowercase()
    )
}

#[allow(clippy::too_many_arguments)]
fn country_block_rule(
    key: &str,
    code: &str,
    networks: &[ipnet::IpNet],
    verdict: Verdict,
    direction: RuleDirection,
    caps: BackendCaps,
    part: usize,
    total: usize,
) -> Result<Rule, EnforceError> {
    // Becomes the rule's description in the Windows Firewall UI. Naming the
    // part makes it obvious that several rows belong to one country rather
    // than looking like duplicates.
    let label = if total > 1 {
        format!("Antiwire {code} country block (part {part} of {total})")
    } else {
        format!("Antiwire {code} country block")
    };
    let mut builder =
        Rule::builder(key, verdict_action(verdict), rule_direction(direction)).label(label);
    if caps.supports_sets() {
        builder = builder.remote_address_set(networks.iter().copied());
    } else {
        for network in networks {
            builder = builder.remote_address(*network);
        }
    }
    let rule = builder
        .build()
        .map_err(|error| EnforceError::InvalidOp(error.to_string()))?;
    debug_assert_eq!(
        caps.supports_sets(),
        rule.address_set_mode() == AddressSetMode::Set
    );
    Ok(rule)
}

fn ip_rule_key(rule_id: i32, ip: &str) -> Result<String, EnforceError> {
    Ok(format!("ir{rule_id:05}{}", encode_ip_suffix(ip)?))
}

fn app_rule_key(rule_id: i32) -> String {
    format!("ar{rule_id:05}")
}

fn dns_rule_key(rule_id: i32) -> String {
    format!("dr{rule_id:05}")
}

/// Key prefix of every `DoH` block rule.
///
/// Those rules exist to keep lookups on Antiwire's resolver, so they are the
/// ones that must not outlive it. See [`crate::firew`].
pub(crate) const DOH_KEY_PREFIX: &str = "dh";

fn doh_block_key(ip: &str, port: u16, protocol: Protocol) -> Result<String, EnforceError> {
    let proto = match protocol {
        Protocol::Tcp => 't',
        Protocol::Udp => 'u',
        _ => {
            return Err(EnforceError::InvalidOp(format!(
                "unsupported DoH block protocol: {protocol:?}"
            )));
        }
    };
    Ok(format!(
        "{DOH_KEY_PREFIX}{}{port:05}{proto}",
        encode_ip_suffix(ip)?
    ))
}

/// Encodes an IP or CIDR into a compact ASCII suffix that fits [`firew_rs::RuleKey`] limits.
fn encode_ip_suffix(ip: &str) -> Result<String, EnforceError> {
    let net = parse_ip_net(ip)?;
    match net {
        IpNet::V4(v4) => {
            let octets = v4.addr().octets();
            Ok(format!(
                "{:03}{:03}{:03}{:03}{:02}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                v4.prefix_len()
            ))
        }
        IpNet::V6(v6) => {
            // All 16 octets plus the prefix length, packed six bits per
            // character. Hex over half the address would fit the key budget but
            // makes distinct prefixes sharing a high half collide, silently
            // overwriting one another in the installed-rule map.
            let mut bytes = [0u8; 17];
            bytes[..16].copy_from_slice(&v6.addr().octets());
            bytes[16] = v6.prefix_len();
            Ok(pack_key_bits(&bytes))
        }
    }
}

/// Alphabet accepted by [`firew_rs::RuleKey`], six bits per character.
const KEY_ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

/// Losslessly packs bytes into rule-key-safe characters.
///
/// 17 bytes become 23 characters, which keeps an IPv6 rule key inside the
/// 32-byte limit while preserving every bit of the address.
fn pack_key_bits(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut accumulator: u32 = 0;
    let mut bits = 0u32;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let index = ((accumulator >> bits) & 0x3F) as usize;
            out.push(char::from(KEY_ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((accumulator << (6 - bits)) & 0x3F) as usize;
        out.push(char::from(KEY_ALPHABET[index]));
    }
    out
}

fn parse_ip_net(ip: &str) -> Result<IpNet, EnforceError> {
    if let Ok(addr) = ip.parse::<IpAddr>() {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        return IpNet::new(addr, prefix)
            .map_err(|error| EnforceError::InvalidOp(format!("invalid IP/CIDR {ip}: {error}")));
    }
    ip.parse::<IpNet>()
        .map_err(|error| EnforceError::InvalidOp(format!("invalid IP/CIDR {ip}: {error}")))
}

fn verdict_action(verdict: Verdict) -> Action {
    if verdict.is_block() {
        Action::Block
    } else {
        Action::Allow
    }
}

/// Maps a policy-level direction onto the portable firewall direction.
fn rule_direction(direction: RuleDirection) -> Direction {
    match direction {
        RuleDirection::Inbound => Direction::Inbound,
        RuleDirection::Outbound => Direction::Outbound,
        RuleDirection::Both => Direction::Both,
    }
}

/// The firewall rule for an IP rule, which never covers this machine's loopback range.
///
/// Windows Firewall does not filter loopback, and macOS ships PF with `set skip on lo0`,
/// but nftables and iptables do see it: there a block on `0.0.0.0/0` also dropped the
/// queries every program sends to Antiwire's resolver on `127.0.0.1`. So the range is taken
/// out of the rule's network on every platform, and a rule is the same rule everywhere.
///
/// Most networks hold no loopback address and stay one address. One that does is split
/// around the range: into an address set where the backend has them, or else one row per
/// part.
fn ip_policy_rule(
    rule_id: i32,
    ip: &str,
    verdict: Verdict,
    direction: RuleDirection,
    caps: BackendCaps,
) -> Result<Rule, EnforceError> {
    let parts = outside_loopback(parse_ip_net(ip)?);
    let builder = Rule::builder(
        ip_rule_key(rule_id, ip)?,
        verdict_action(verdict),
        rule_direction(direction),
    );
    let builder = match parts.as_slice() {
        [] => {
            return Err(EnforceError::InvalidOp(format!(
                "{ip} is this machine's loopback range, which firewall rules do not cover"
            )));
        }
        [net] => builder.remote_address(*net),
        _ if caps.supports_sets() => builder.remote_address_set(parts),
        _ => parts
            .into_iter()
            .fold(builder, firew_rs::RuleBuilder::remote_address),
    };
    builder
        .build()
        .map_err(|error| EnforceError::InvalidOp(error.to_string()))
}

/// The parts of `net` outside the loopback range of its address family: `127.0.0.0/8`, or
/// `::1`. Empty when `net` lies inside the range.
fn outside_loopback(net: IpNet) -> Vec<IpNet> {
    let loopback = match net {
        IpNet::V4(_) => IpNet::V4(ipnet::Ipv4Net::new_assert(
            std::net::Ipv4Addr::new(127, 0, 0, 0),
            8,
        )),
        IpNet::V6(_) => IpNet::V6(ipnet::Ipv6Net::new_assert(
            std::net::Ipv6Addr::LOCALHOST,
            128,
        )),
    };
    let mut parts = Vec::new();
    collect_outside(net.trunc(), loopback, &mut parts);
    parts
}

/// Adds the parts of `net` that lie outside `hole` to `parts`: `net` itself when the two do
/// not meet, and otherwise what each of its halves leaves, down to `hole`.
fn collect_outside(net: IpNet, hole: IpNet, parts: &mut Vec<IpNet>) {
    if hole.contains(&net) {
        return;
    }
    if !net.contains(&hole) {
        parts.push(net);
        return;
    }
    // `net` holds `hole` and is larger, so it has a longer prefix to split at.
    if let Ok(halves) = net.subnets(net.prefix_len() + 1) {
        for half in halves {
            collect_outside(half, hole, parts);
        }
    }
}

fn app_policy_rule(
    rule_id: i32,
    app_path: &str,
    verdict: Verdict,
    direction: RuleDirection,
) -> Result<Rule, EnforceError> {
    Rule::builder(
        app_rule_key(rule_id),
        verdict_action(verdict),
        rule_direction(direction),
    )
    .application_path(app_path)
    .build()
    .map_err(|error| EnforceError::InvalidOp(error.to_string()))
}

fn doh_block_rule(ip: &str, port: u16, protocol: Protocol) -> Result<Rule, EnforceError> {
    let net = parse_ip_net(ip)?;
    let port_range =
        PortRange::single(port).map_err(|error| EnforceError::InvalidOp(error.to_string()))?;
    Rule::builder(
        doh_block_key(ip, port, protocol)?,
        Action::Block,
        Direction::Outbound,
    )
    .protocol(protocol)
    .remote_address(net)
    .remote_port(port_range)
    .build()
    .map_err(|error| EnforceError::InvalidOp(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use firew_rs::Action;

    #[test]
    fn maps_ip_allow_rule() {
        let rules = apply_op(
            &EnforcementOp::AddIpRule {
                rule_id: 7,
                ip: "10.0.0.0/8".to_owned(),
                verdict: Verdict::Allow,
                direction: RuleDirection::Outbound,
            },
            BackendCaps::default(),
        )
        .expect("valid ip rule");

        assert_eq!(rules[0].1.action(), Action::Allow);
        assert_eq!(rules[0].0, "ir0000701000000000008");
    }

    fn ip_rule(ip: &str, caps: BackendCaps) -> Result<Rule, EnforceError> {
        ip_policy_rule(1, ip, Verdict::Block, RuleDirection::Both, caps)
    }

    fn nets(rule: &Rule) -> Vec<String> {
        rule.remote_addresses()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    const SETS: BackendCaps = BackendCaps {
        max_address_set_entries: Some(65_536),
        ipv4_only: false,
    };

    /// Blocking every address used to drop the queries programs send to the resolver on
    /// `127.0.0.1` wherever the firewall filters loopback.
    #[test]
    fn a_rule_for_every_ipv4_address_leaves_loopback_out() {
        let rule = ip_rule("0.0.0.0/0", SETS).expect("rule");
        assert_eq!(rule.address_set_mode(), AddressSetMode::Set);
        assert_eq!(
            nets(&rule),
            [
                "0.0.0.0/2",
                "64.0.0.0/3",
                "96.0.0.0/4",
                "112.0.0.0/5",
                "120.0.0.0/6",
                "124.0.0.0/7",
                "126.0.0.0/8",
                "128.0.0.0/1"
            ]
        );

        // The same parts as single rows where the backend has no address sets.
        let rows = ip_rule("0.0.0.0/0", BackendCaps::default()).expect("rule");
        assert_eq!(rows.address_set_mode(), AddressSetMode::Cartesian);
        assert_eq!(nets(&rows), nets(&rule));
    }

    #[test]
    fn a_rule_for_every_ipv6_address_leaves_loopback_out() {
        let rule = ip_rule("::/0", SETS).expect("rule");
        let loopback: IpNet = "::1/128".parse().expect("net");
        assert_eq!(rule.remote_addresses().len(), 128);
        assert!(rule
            .remote_addresses()
            .iter()
            .all(|net| !net.contains(&loopback)));
        // Every other address is still covered: the parts add up to all but one.
        let covered: u128 = rule
            .remote_addresses()
            .iter()
            .map(|net| 1u128 << (128 - u32::from(net.prefix_len())))
            .fold(0, u128::wrapping_add);
        assert_eq!(covered, u128::MAX);
    }

    #[test]
    fn a_network_without_loopback_stays_one_address() {
        for target in ["10.0.0.0/8", "203.0.113.7", "128.0.0.0/1", "2001:db8::/32"] {
            let rule = ip_rule(target, SETS).expect("rule");
            assert_eq!(
                rule.address_set_mode(),
                AddressSetMode::Cartesian,
                "{target}"
            );
            assert_eq!(rule.remote_addresses().len(), 1, "{target}");
        }
    }

    #[test]
    fn a_rule_inside_loopback_is_refused() {
        for target in ["127.0.0.1", "127.0.0.0/8", "127.8.0.0/16", "::1"] {
            let error = ip_rule(target, SETS).expect_err(target);
            assert!(matches!(error, EnforceError::InvalidOp(_)), "{target}");
        }
    }

    #[test]
    fn honours_inbound_and_bidirectional_rules() {
        let inbound = apply_op(
            &EnforcementOp::AddIpRule {
                rule_id: 11,
                ip: "203.0.113.0/24".to_owned(),
                verdict: Verdict::Block,
                direction: RuleDirection::Inbound,
            },
            BackendCaps::default(),
        )
        .expect("inbound ip rule");
        assert_eq!(inbound[0].1.direction(), Direction::Inbound);

        let both = apply_op(
            &EnforcementOp::AddAppRule {
                rule_id: 12,
                app_path: "/bin/curl".to_owned(),
                verdict: Verdict::Block,
                direction: RuleDirection::Both,
            },
            BackendCaps::default(),
        )
        .expect("bidirectional app rule");
        assert_eq!(both[0].1.direction(), Direction::Both);
    }

    #[test]
    fn maps_doh_block_to_tcp_and_udp_rules() {
        let rules = apply_op(
            &EnforcementOp::AddDohBlock {
                doh_ips: vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
                port: 443,
            },
            BackendCaps::default(),
        )
        .expect("valid doh block");

        assert_eq!(rules.len(), 4);
        assert!(rules.iter().all(|(_, rule)| rule.action() == Action::Block));
        assert!(rules.iter().any(|(key, _)| key == "dh0010010010013200443t"));
    }

    #[test]
    fn leftover_dns_remove_uses_stable_dr_key() {
        let keys = op_rule_keys(&EnforcementOp::RemoveDnsRule {
            rule_id: 13,
            domain: "example.test".to_owned(),
        })
        .expect("dns remove key");
        assert_eq!(keys, ["dr00013"]);
    }

    #[test]
    fn maps_app_ops_to_firewall_rules() {
        let app_rules = apply_op(
            &EnforcementOp::AddAppRule {
                rule_id: 2,
                app_path: "/bin/curl".to_owned(),
                verdict: Verdict::Allow,
                direction: RuleDirection::Outbound,
            },
            BackendCaps::default(),
        )
        .expect("app op");
        assert_eq!(app_rules.len(), 1);
        assert_eq!(
            app_rules[0].1.application_path(),
            Some(std::path::Path::new("/bin/curl"))
        );
        assert_eq!(app_rules[0].1.action(), Action::Allow);
    }

    #[test]
    fn ipv6_keys_no_longer_collide_on_a_shared_high_half() {
        // These differ only in the low 8 octets. Encoding just the first half
        // made them the same key, so one rule silently replaced the other.
        let a = ip_rule_key(1, "2001:db8::1/128").expect("key a");
        let b = ip_rule_key(1, "2001:db8::2/128").expect("key b");
        assert_ne!(a, b);

        // Same high half, different prefix length.
        let c = ip_rule_key(1, "2001:db8::/64").expect("key c");
        let d = ip_rule_key(1, "2001:db8::/48").expect("key d");
        assert_ne!(c, d);
    }

    #[test]
    fn ipv6_keys_fit_the_rule_key_limit_and_charset() {
        for target in [
            "2001:db8::1/128",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
            "::/0",
        ] {
            let key = ip_rule_key(99_999, target).expect("key");
            assert!(key.len() <= 32, "{key} is {} chars", key.len());
            assert!(
                key.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "{key} has characters a RuleKey rejects"
            );
            assert!(firew_rs::RuleKey::try_from(key.as_str()).is_ok());
        }
    }

    #[test]
    fn country_keys_read_as_names_a_person_can_recognise() {
        // The logical key is embedded in the native rule name, so this is what
        // shows up in the Windows Firewall UI.
        assert_eq!(country_block_key("US", 0), "antiwire-us-rules-1");
        assert_eq!(country_block_key("US", 1), "antiwire-us-rules-2");
        assert_eq!(country_block_key("kp", 0), "antiwire-kp-rules-1");

        for key in [
            country_block_key("US", 0),
            country_block_key("US", u16::MAX),
        ] {
            assert!(key.starts_with(&country_key_prefix("US")));
            assert!(key.len() <= 32, "{key} is {} chars", key.len());
            assert!(firew_rs::RuleKey::try_from(key.as_str()).is_ok());
        }
    }

    #[test]
    fn a_split_country_names_each_part_in_its_description() {
        let networks: Vec<IpNet> = (0..3)
            .map(|index: u32| {
                let octets = index.to_be_bytes();
                IpNet::new(
                    std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect();
        let caps = BackendCaps {
            max_address_set_entries: Some(1),
            ipv4_only: false,
        };

        let rules = apply_country_op(
            "US",
            &networks,
            Verdict::Block,
            RuleDirection::Outbound,
            caps,
        )
        .expect("country rules");

        assert_eq!(
            rules
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>(),
            vec![
                "antiwire-us-rules-1",
                "antiwire-us-rules-2",
                "antiwire-us-rules-3"
            ]
        );
        assert_eq!(
            rules[0].1.label(),
            Some("Antiwire US country block (part 1 of 3)")
        );
        assert_eq!(
            rules[2].1.label(),
            Some("Antiwire US country block (part 3 of 3)")
        );
    }

    #[test]
    fn a_single_part_country_omits_the_part_suffix() {
        let networks = vec!["203.0.113.0/24".parse::<IpNet>().expect("net")];
        let rules = apply_country_op(
            "KP",
            &networks,
            Verdict::Block,
            RuleDirection::Both,
            BackendCaps {
                max_address_set_entries: Some(10_000),
                ipv4_only: false,
            },
        )
        .expect("country rules");

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, "antiwire-kp-rules-1");
        assert_eq!(rules[0].1.label(), Some("Antiwire KP country block"));
    }

    #[test]
    fn a_set_capable_backend_maps_a_country_to_one_rule() {
        let networks: Vec<IpNet> = (0..5_000)
            .map(|index: u32| {
                let octets = index.to_be_bytes();
                IpNet::new(
                    std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect();
        let caps = BackendCaps {
            max_address_set_entries: Some(65_536),
            ipv4_only: false,
        };

        let rules = apply_country_op("US", &networks, Verdict::Block, RuleDirection::Both, caps)
            .expect("country rules");

        assert_eq!(rules.len(), 1);
        let (_, rule) = &rules[0];
        assert_eq!(rule.address_set_mode(), AddressSetMode::Set);
        assert_eq!(rule.remote_addresses().len(), 5_000);
        assert_eq!(rule.direction(), Direction::Both);
        assert_eq!(rule.action(), Action::Block);
        assert_eq!(rule.label(), Some("Antiwire US country block"));
    }

    #[test]
    fn a_backend_without_sets_chunks_the_country() {
        let networks: Vec<IpNet> = (0..200)
            .map(|index: u32| {
                let octets = index.to_be_bytes();
                IpNet::new(
                    std::net::Ipv4Addr::new(10, octets[1], octets[2], octets[3]).into(),
                    32,
                )
                .expect("net")
            })
            .collect();

        let rules = apply_country_op(
            "US",
            &networks,
            Verdict::Block,
            RuleDirection::Outbound,
            BackendCaps::default(),
        )
        .expect("country rules");

        assert!(rules.len() > 1);
        assert_eq!(
            rules
                .iter()
                .map(|(_, rule)| rule.remote_addresses().len())
                .sum::<usize>(),
            200
        );
        assert!(rules
            .iter()
            .all(|(_, rule)| rule.address_set_mode() == AddressSetMode::Cartesian));
        // Keys must stay distinct or chunks would overwrite one another.
        let keys: std::collections::HashSet<&String> = rules.iter().map(|(k, _)| k).collect();
        assert_eq!(keys.len(), rules.len());
    }
}
