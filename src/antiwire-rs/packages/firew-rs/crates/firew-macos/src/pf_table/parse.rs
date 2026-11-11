//! Reconstructing managed rules from `pfctl` listings.

use std::collections::{BTreeMap, HashMap};

use firew_core::{Action, Direction, Error, ErrorKind, PortRange, Protocol, Rule, RuleKey};
use firew_sys::{parse_native_net, ManagedMarker, ManagedNamespace};
use ipnet::IpNet;

use super::render::{cartesian_addr_family_word, set_addr_family_word};
use super::AnchorListing;

/// Reconstructs logical [`Rule`]s from `pfctl -s rules` text output and a table loader.
///
/// # Errors
///
/// Returns an error when `load_table` fails.
pub fn reconstruct_anchor_text<F>(
    rules_text: &str,
    namespace: &ManagedNamespace,
    load_table: F,
) -> Result<AnchorListing, Error>
where
    F: Fn(&str) -> Result<Option<Vec<IpNet>>, Error>,
{
    let mut inline_tables: HashMap<String, Vec<IpNet>> = HashMap::new();
    let mut grouped: BTreeMap<RuleKey, Vec<ParsedPfRow>> = BTreeMap::new();
    let mut lines_by_key: BTreeMap<RuleKey, Vec<String>> = BTreeMap::new();
    let mut listing = AnchorListing::default();
    let mut poisoned_keys: std::collections::HashSet<RuleKey> = std::collections::HashSet::new();

    for raw_line in rules_text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((table_name, nets)) = parse_inline_table_line(line) {
            inline_tables.insert(table_name, nets);
            continue;
        }
        match parse_pf_rule_line(line, namespace) {
            Ok(row) => {
                lines_by_key
                    .entry(row.marker.key.clone())
                    .or_default()
                    .push(line.to_owned());
                grouped.entry(row.marker.key.clone()).or_default().push(row);
            }
            Err(maybe_key) => {
                if let Some(key) = &maybe_key {
                    poisoned_keys.insert(key.clone());
                }
                listing.drifted.push(line.to_owned());
                listing.unrecognized.push((maybe_key, line.to_owned()));
            }
        }
    }

    for (key, rows) in grouped {
        let rebuilt = if poisoned_keys.contains(&key) {
            None
        } else {
            rebuild_rule(&key, rows, &inline_tables, &load_table)?
        };
        if let Some(rule) = rebuilt {
            listing.rules.insert(key, rule);
        } else {
            listing.drifted.push(key.to_string());
            for line in lines_by_key.remove(&key).unwrap_or_default() {
                listing.unrecognized.push((Some(key.clone()), line));
            }
        }
    }

    Ok(listing)
}

/// Rebuilds one logical rule from its rows, or `None` when they are
/// incomplete or inconsistent.
fn rebuild_rule<F>(
    key: &RuleKey,
    mut rows: Vec<ParsedPfRow>,
    inline_tables: &HashMap<String, Vec<IpNet>>,
    load_table: &F,
) -> Result<Option<Rule>, Error>
where
    F: Fn(&str) -> Result<Option<Vec<IpNet>>, Error>,
{
    let rebuilt = firew_sys::rebuild_rule(key, &mut rows, |rows| {
        let Some(table_name) = &rows[0].remote_table else {
            return Ok(None);
        };
        Ok(Some(match inline_tables.get(table_name) {
            Some(inline) => inline.clone(),
            None => load_table(table_name)?.unwrap_or_default(),
        }))
    });
    match rebuilt {
        Ok(rule) => Ok(rows
            .iter()
            .all(|row| row.addr_family == expected_addr_family(&rule, row))
            .then_some(rule)),
        Err(error) if error.kind() == ErrorKind::CorruptNativeState => Ok(None),
        Err(error) => Err(error),
    }
}

/// The address family word the renderer writes for `row` of `rule`. A
/// different one restricts the row to one family, or widens it.
fn expected_addr_family(rule: &Rule, row: &ParsedPfRow) -> Option<&'static str> {
    if row.remote_table.is_some() {
        set_addr_family_word(rule, row.local_address.as_ref())
    } else {
        cartesian_addr_family_word(
            rule.protocol(),
            row.remote_address.as_ref(),
            row.local_address.as_ref(),
        )
    }
}

fn parse_inline_table_line(line: &str) -> Option<(String, Vec<IpNet>)> {
    let rest = line.strip_prefix("table <")?;
    let (name, after_name) = rest.split_once('>')?;
    let (_, inside_braces) = after_name.split_once('{')?;
    let (entries_str, _) = inside_braces.rsplit_once('}')?;
    let nets: Vec<IpNet> = entries_str
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .filter_map(parse_native_net)
        .collect();
    Some((name.to_owned(), nets))
}

firew_sys::impl_native_row!(ParsedPfRow, remote_set = remote_table);

struct ParsedPfRow {
    marker: ManagedMarker,
    action: Action,
    direction: Direction,
    protocol: Protocol,
    remote_address: Option<IpNet>,
    local_address: Option<IpNet>,
    remote_port: Option<PortRange>,
    local_port: Option<PortRange>,
    remote_table: Option<String>,
    /// `inet` or `inet6` when the line names an address family.
    addr_family: Option<&'static str>,
}

/// Parses one `pfctl -s rules` line. `Err(None)` is a line without a marker
/// of this namespace; `Err(Some(key))` is a line carrying the marker of `key`
/// that does not parse, so that key has drifted.
fn parse_pf_rule_line(
    line: &str,
    namespace: &ManagedNamespace,
) -> Result<ParsedPfRow, Option<RuleKey>> {
    // Extract label "..." first so we know if a broken rule still belongs to a known key.
    let (body, label) = split_label(line).ok_or(None)?;
    let marker = ManagedMarker::parse(label, namespace).map_err(|_| None)?;
    let key = marker.key.clone();
    parse_pf_rule_body(body, marker).ok_or(Some(key))
}

/// Splits a rule line into its body and the value of its `label "..."`.
///
/// `pfctl` prints the label after every matching option, so text after it
/// (`tagged`, `rtable`, ...) is an option the managed rule never has, and the
/// line is refused.
fn split_label(line: &str) -> Option<(&str, &str)> {
    let label_idx = line.find("label \"")?;
    let after_label = &line[label_idx + 7..];
    let quote_end = after_label.find('"')?;
    after_label[quote_end + 1..]
        .trim()
        .is_empty()
        .then(|| (line[..label_idx].trim(), &after_label[..quote_end]))
}

fn parse_pf_rule_body(body: &str, marker: ManagedMarker) -> Option<ParsedPfRow> {
    let mut tokens = PfTokens::new(body);
    let action = if tokens.eat("pass") {
        Action::Allow
    } else if tokens.eat("block") {
        if tokens.eat("return") {
            Action::Reject
        } else {
            tokens.skip_any(&["drop"]);
            Action::Block
        }
    } else {
        return None;
    };
    let direction = if tokens.eat("in") {
        Direction::Inbound
    } else if tokens.eat("out") {
        Direction::Outbound
    } else {
        return None;
    };
    // Must have `quick` for managed rules; if someone removed `quick`, treat as drift!
    if !tokens.eat("quick") {
        return None;
    }
    let addr_family = if tokens.eat("inet") {
        Some("inet")
    } else if tokens.eat("inet6") {
        Some("inet6")
    } else {
        None
    };
    let protocol = if tokens.eat("proto") {
        parse_pf_protocol(tokens.next()?)?
    } else {
        Protocol::Any
    };

    if !tokens.eat("from") {
        return None;
    }
    let from_target = tokens.next()?;
    let from_port = tokens.port().ok()?;
    if !tokens.eat("to") {
        return None;
    }
    let to_target = tokens.next()?;
    let to_port = tokens.port().ok()?;
    // `pfctl` adds `flags S/SA keep state` to a `pass` rule loaded without
    // state options. Anything else after the endpoints, such as `user = 501`,
    // narrows what the rule matches.
    if tokens.eat("flags") && !tokens.eat("S/SA") {
        return None;
    }
    if tokens.eat("keep") && !tokens.eat("state") {
        return None;
    }
    if tokens.next().is_some() {
        return None;
    }

    let (remote_tok, remote_port, local_tok, local_port) = match direction {
        Direction::Inbound => (from_target, from_port, to_target, to_port),
        Direction::Outbound | Direction::Both => (to_target, to_port, from_target, from_port),
    };
    let (remote_address, remote_table) = match remote_tok {
        "any" => (None, None),
        table if table.starts_with('<') => (
            None,
            Some(table.strip_prefix('<')?.strip_suffix('>')?.to_owned()),
        ),
        address => (Some(parse_native_net(address)?), None),
    };
    let local_address = match local_tok {
        "any" => None,
        address => Some(parse_native_net(address)?),
    };

    Some(ParsedPfRow {
        marker,
        action,
        direction,
        protocol,
        remote_address,
        local_address,
        remote_port,
        local_port,
        remote_table,
        addr_family,
    })
}

fn parse_pf_protocol(token: &str) -> Option<Protocol> {
    Some(match token {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "icmp" => Protocol::IcmpV4,
        "icmp6" | "ipv6-icmp" => Protocol::IcmpV6,
        other => Protocol::Other(other.parse::<u8>().ok()?).canonicalize(),
    })
}

/// A cursor over the whitespace-separated words of a rule body.
struct PfTokens<'a> {
    words: Vec<&'a str>,
    next: usize,
}

impl<'a> PfTokens<'a> {
    fn new(body: &'a str) -> Self {
        Self {
            words: body.split_whitespace().collect(),
            next: 0,
        }
    }

    fn next(&mut self) -> Option<&'a str> {
        let word = self.words.get(self.next).copied()?;
        self.next += 1;
        Some(word)
    }

    /// Consumes the next word when it is `word`.
    fn eat(&mut self, word: &str) -> bool {
        let matched = self.words.get(self.next) == Some(&word);
        if matched {
            self.next += 1;
        }
        matched
    }

    /// Consumes the next word when it is any of `words`.
    fn skip_any(&mut self, words: &[&str]) {
        if self
            .words
            .get(self.next)
            .is_some_and(|word| words.contains(word))
        {
            self.next += 1;
        }
    }

    /// An optional `port = N`, `port N`, or `port LOW:HIGH` clause. A clause
    /// that is present but malformed is an error.
    fn port(&mut self) -> Result<Option<PortRange>, ()> {
        if !self.eat("port") {
            return Ok(None);
        }
        let mut token = self.next().ok_or(())?;
        if token == "=" {
            token = self.next().ok_or(())?;
        }
        let range = match token.split_once(':') {
            Some((low, high)) => {
                let low = low.parse::<u16>().map_err(|_| ())?;
                let high = high.parse::<u16>().map_err(|_| ())?;
                PortRange::range(low, high)
            }
            None => PortRange::single(token.parse::<u16>().map_err(|_| ())?),
        };
        range.map(Some).map_err(|_| ())
    }
}
