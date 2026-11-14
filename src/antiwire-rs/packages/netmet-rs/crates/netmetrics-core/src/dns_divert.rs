//! Port-53 divert rules shared by the platform backends.
//!
//! The strings are platform commands, but they contain no OS calls, so the
//! Windows test suite can still check that shutdown removes the rule.

/// What a running port-53 divert tells its owner after it started.
///
/// Each event marks a change. While the divert is lost, DNS that bypasses the stub reaches the
/// resolver it was sent to, and port 853 is open. On Linux and macOS a loss is reported once,
/// and the first failure to restore it once; Windows reports every attempt that fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DivertEvent {
    /// The divert stopped working, for the reason given, and is being put back.
    Lost(String),
    /// The divert works again after a loss.
    Restored,
    /// Putting the divert back failed, for the reason given. It is tried again.
    RestoreFailed(String),
}

/// Receives a divert's [`DivertEvent`]s, on a thread the divert owns.
pub type DivertReport = Box<dyn Fn(DivertEvent) + Send + 'static>;

/// The socket mark the Linux divert lets through: the one exemption it has.
///
/// The stub sets it on the sockets it reaches its upstream resolver through, so that its own
/// lookups are not sent back to it and can use port 853. `socket(7)`, `SO_MARK`: "Set the
/// mark for each packet sent through this socket", which needs `CAP_NET_ADMIN` or, since
/// Linux 5.17, `CAP_NET_RAW`. Loading the divert's rules needs `CAP_NET_ADMIN` too, so a
/// process that can install the divert can mark its sockets, and one that cannot mark them
/// has no divert to be exempt from.
///
/// The exemption used to be every process of root. A root process that asked another
/// resolver directly then got an answer no rule or blocklist had seen, with nothing in the
/// history, and could use DNS over TLS.
///
/// The value is arbitrary. A host that routes or filters by mark sees the stub's upstream
/// sockets under it.
pub const LINUX_DNS_DIVERT_EXEMPT_MARK: u32 = 0x0000_2035;

/// nftables script installed while the stub is running.
///
/// Packets of a socket marked [`LINUX_DNS_DIVERT_EXEMPT_MARK`] are returned unchanged, so
/// the stub can still reach an upstream resolver. Traffic already addressed to the stub is
/// not matched. `nft(8)`, META EXPRESSIONS: `mark` is the packet mark, which a packet takes
/// from its socket.
#[must_use]
pub fn linux_dns_divert_ruleset() -> &'static str {
    "table inet antiwire_dns\n\
     delete table inet antiwire_dns\n\
     table inet antiwire_dns {\n\
     \tchain output {\n\
     \t\ttype nat hook output priority dstnat; policy accept;\n\
     \t\tmeta mark 0x00002035 return\n\
     \t\tudp dport 53 ip daddr != 127.0.0.1 redirect to :53\n\
     \t\ttcp dport 53 ip daddr != 127.0.0.1 redirect to :53\n\
     \t\tudp dport 53 ip6 daddr != ::1 redirect to :53\n\
     \t\ttcp dport 53 ip6 daddr != ::1 redirect to :53\n\
     \t}\n\
     \tchain output_filter {\n\
     \t\ttype filter hook output priority filter; policy accept;\n\
     \t\tmeta mark 0x00002035 return\n\
     \t\ttcp dport 853 drop\n\
     \t\tudp dport 853 drop\n\
     \t}\n\
     }\n"
}

/// `nft` arguments that remove the Linux divert.
#[must_use]
pub fn linux_dns_divert_disable_args() -> [&'static str; 4] {
    ["delete", "table", "inet", "antiwire_dns"]
}

/// `nft` arguments that load [`linux_dns_divert_ruleset`] from standard input.
///
/// `nft(8)`: `-f -` reads the script from standard input. nft applies a script as one
/// transaction, so the table is replaced whole or not at all.
#[must_use]
pub fn linux_dns_divert_install_args() -> [&'static str; 2] {
    ["-f", "-"]
}

/// `nft` arguments that print the divert's table: its flags, chains, hooks, policies and rules.
///
/// `nft(8)`: `list table` prints all chains and rules of the table, without handles unless
/// `-a` is given. The divert compares this listing with the one it took after installing the
/// table, so it parses nothing in it.
#[must_use]
pub fn linux_dns_divert_list_args() -> [&'static str; 4] {
    ["list", "table", "inet", "antiwire_dns"]
}

/// Where distributions install `nft`, tried in this order.
///
/// Debian, Ubuntu, Fedora (`%{_sbindir}`), openSUSE and Alpine package it as `/usr/sbin/nft`,
/// Arch as `/usr/bin/nft`. `/sbin/nft` covers a system whose `/sbin` is not merged into `/usr`.
/// A privileged process must not look the program up on `PATH`.
pub const LINUX_NFT_PATHS: [&str; 3] = ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft"];

/// The chain the iptables form of the Linux divert keeps in the `nat` and `filter` tables.
pub const LINUX_IPTABLES_DIVERT_CHAIN: &str = "ANTIWIRE_DNS";

/// The directories distributions install the iptables programs in, tried in this order.
///
/// Debian, Ubuntu and Fedora put them in `/usr/sbin`, Arch in `/usr/bin`, and `/sbin` covers
/// a system whose `/sbin` is not merged into `/usr`. A privileged process must not look a
/// program up on `PATH`.
pub const LINUX_IPTABLES_DIRS: [&str; 3] = ["/usr/sbin", "/usr/bin", "/sbin"];

/// One address family of the iptables form of the Linux divert. iptables keeps the rules of
/// each family apart and has a set of programs for each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxIptablesFamily {
    /// IPv4: `iptables`.
    V4,
    /// IPv6: `ip6tables`.
    V6,
}

impl LinuxIptablesFamily {
    /// Both families. The divert needs the two, or DNS sent over the other one bypasses it.
    pub const ALL: [Self; 2] = [Self::V4, Self::V6];

    /// The program that changes one rule or chain, `iptables(8)`.
    #[must_use]
    pub fn rule_program(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    /// The program that loads rules from standard input, `iptables-restore(8)`.
    #[must_use]
    pub fn restore_program(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }

    /// The program that prints a table's rules, `iptables-save(8)`.
    #[must_use]
    pub fn save_program(self) -> &'static str {
        match self {
            Self::V4 => "iptables-save",
            Self::V6 => "ip6tables-save",
        }
    }

    /// The address the stub listens on in this family, as a network.
    fn stub_network(self) -> &'static str {
        match self {
            Self::V4 => "127.0.0.1/32",
            Self::V6 => "::1/128",
        }
    }
}

/// The tables the iptables form of the divert has a chain in.
pub const LINUX_IPTABLES_DIVERT_TABLES: [&str; 2] = ["nat", "filter"];

/// `iptables-restore` input that installs one family of the divert, for a host without `nft`.
///
/// The rules are those of [`linux_dns_divert_ruleset`], in a chain of their own in each
/// table, which the built-in `OUTPUT` chain jumps to first:
///
/// - `iptables-extensions(8)`, `mark`: "Matches packets with the given unsigned mark
///   value". Packets of a socket marked [`LINUX_DNS_DIVERT_EXEMPT_MARK`] return to `OUTPUT`
///   unchanged, so the stub still reaches its upstream.
/// - `iptables-extensions(8)`, `REDIRECT`: valid "in the nat table, in the PREROUTING and
///   OUTPUT chains, and user-defined chains which are only called from those chains", and
///   "locally-generated packets are mapped to the localhost address, 127.0.0.1 for IPv4 and
///   `::1` for IPv6". `--to-ports` needs the rule to name the protocol, which each does.
/// - The jump is inserted at the head of `OUTPUT` (`-I OUTPUT 1`): a rule of the host's own
///   that accepts outgoing traffic would otherwise end the chain before it.
///
/// Each table is a transaction of its own (`COMMIT`), so `nat` can load and `filter` fail.
/// The caller removes what was loaded before it reports the failure. The script only adds:
/// it is loaded with `--noflush`, after the chains it names have been removed.
#[must_use]
pub fn linux_iptables_divert_script(family: LinuxIptablesFamily) -> String {
    let chain = LINUX_IPTABLES_DIVERT_CHAIN;
    let stub = family.stub_network();
    let exempt = LINUX_DNS_DIVERT_EXEMPT_MARK;
    format!(
        "*nat\n\
         :{chain} - [0:0]\n\
         -A {chain} -m mark --mark {exempt:#x} -j RETURN\n\
         -A {chain} ! -d {stub} -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n\
         -A {chain} ! -d {stub} -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53\n\
         -I OUTPUT 1 -j {chain}\n\
         COMMIT\n\
         *filter\n\
         :{chain} - [0:0]\n\
         -A {chain} -m mark --mark {exempt:#x} -j RETURN\n\
         -A {chain} -p tcp -m tcp --dport 853 -j DROP\n\
         -A {chain} -p udp -m udp --dport 853 -j DROP\n\
         -I OUTPUT 1 -j {chain}\n\
         COMMIT\n"
    )
}

/// `iptables-restore` arguments that load [`linux_iptables_divert_script`] from standard input.
///
/// `iptables-restore(8)`: `--noflush` keeps "the previous contents of the table", which are
/// the host's own rules, and `--wait` waits for the xtables lock another iptables holds.
#[must_use]
pub fn linux_iptables_divert_install_args() -> [&'static str; 2] {
    ["--wait", "--noflush"]
}

/// `iptables-save` arguments that print one table, the form the divert reads its rules back
/// in. `iptables-save(8)`: `-t` restricts "output to only one table".
#[must_use]
pub fn linux_iptables_divert_save_args(table: &str) -> [&str; 2] {
    ["-t", table]
}

/// The `iptables` calls that remove the divert's chain from `table`, in the order they have to
/// run: the jump out of `OUTPUT`, then the chain's rules, then the chain.
///
/// `iptables(8)`, `-X`: "There must be no references to the chain", and "The chain must be
/// empty". Each call fails when what it removes is not there, which is what a second removal
/// finds.
#[must_use]
pub fn linux_iptables_divert_remove_args(table: &str) -> [Vec<&str>; 3] {
    let chain = LINUX_IPTABLES_DIVERT_CHAIN;
    [
        vec!["--wait", "-t", table, "-D", "OUTPUT", "-j", chain],
        vec!["--wait", "-t", table, "-F", chain],
        vec!["--wait", "-t", table, "-X", chain],
    ]
}

/// The lines of an `iptables-save` listing that belong to the divert: the rules of its chain
/// and the jump to it, in listing order.
///
/// The chain's own line (`:ANTIWIRE_DNS - [0:0]`) is left out, because it carries packet
/// counters that change as the divert works. The divert compares what is left with what it
/// read after installing, so a removed, emptied or unhooked chain shows up as a difference.
#[must_use]
pub fn linux_iptables_divert_rules(listing: &str) -> String {
    listing
        .lines()
        .filter(|line| {
            line.starts_with("-A ")
                && line
                    .split_ascii_whitespace()
                    .any(|word| word == LINUX_IPTABLES_DIVERT_CHAIN)
        })
        .fold(String::new(), |mut rules, line| {
            rules.push_str(line);
            rules.push('\n');
            rules
        })
}

/// pf anchor rules that hand the stub the DNS this host would send to another resolver.
///
/// pf cannot redirect a query as it leaves the host. `pf.conf(5)` evaluates `rdr`
/// rules "on an inbound packet", and its `rdr-rule` grammar has no `user` option, so a
/// translation rule cannot tell root's queries from anyone else's: pfctl rejects the whole
/// anchor when one tries. XNU (`bsd/net/pf.c`, `pf_match_translation`) does try `rdr` rules on
/// outbound packets, but only as replies from the rule's target, and it rewrites their source,
/// never their destination.
///
/// So the work is split, as `pf.conf(5)` allows:
///
/// - The `pass ... route-to` rule takes a query that a process other than root sends to port 53
///   out of any interface but `lo0`, and routes it to `lo0` instead. It is `quick`, so a later
///   `pass` elsewhere in the ruleset cannot send the query out after all.
/// - The `rdr` rule takes port-53 packets that arrive on `lo0` for an address outside
///   loopback, and sends them to the stub's port 53. The client's source address and port are
///   left as they were, and the state the rule creates makes the stub's answer come back from
///   the address the client asked.
///
/// The `rdr` rule also names the source, and leaves out loopback: a routed query keeps the
/// address of the interface it was leaving by, so none comes from loopback. Without that, the
/// outbound match described above caught the stub's own UDP answer to a client on loopback,
/// which is how the system resolver asks: the answer got a state from the stub's port 53 to
/// the stub's port 53 and never reached the client, so no name resolved while the divert was
/// in place. TCP answers and diverted queries were not affected. Seen on macOS 26.3 and 27.0.
///
/// The `rdr` rule goes by destination because it cannot be told which packets the first rule
/// routed. A tag set as a packet leaves is gone when it arrives: `lo_output` (XNU
/// `bsd/net/if_loop.c`) reports the transmit status with `mbuf_set_status`, which clears the
/// driver's part of the packet header (`driver_mtag_init`, `bsd/kern/kpi_mbuf.c`), and the pf
/// tag lies in the same union (`union builtin_mtag`, `bsd/sys/mbuf.h`). Nor can pf be asked
/// for "not one of this host's addresses": XNU never fills the table behind `(self)`
/// (`pfi_table_update` in `bsd/net/pf_if.c` adds addresses only for a single interface).
///
/// Root's queries that leave the host, which include the stub's own upstream lookups, are not
/// routed, and a query to a loopback address, the stub's included, is not redirected. A query
/// this host sends to one of its own other addresses also arrives on `lo0`, and is diverted
/// like one that was routed there, whoever sent it: a translation rule cannot match the user.
/// So a resolver on this host that the stub forwards to has to be reached on loopback. Port
/// 853, where DNS over TLS and over QUIC run, is dropped for every process but root's.
///
/// Translation rules come first because pfctl enforces that order by default (`pf.conf(5)`,
/// `set require-order`).
#[must_use]
pub fn macos_dns_divert_rules() -> &'static str {
    "rdr pass on lo0 inet proto { tcp, udp } from ! 127.0.0.0/8 to ! 127.0.0.0/8 port 53 -> 127.0.0.1 port 53\n\
     rdr pass on lo0 inet6 proto { tcp, udp } from ! ::1 to ! ::1 port 53 -> ::1 port 53\n\
     pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto { tcp, udp } from any to any port 53 user != root\n\
     pass out quick on ! lo0 route-to (lo0 ::1) inet6 proto { tcp, udp } from any to any port 53 user != root\n\
     block drop out inet proto { tcp, udp } from any to any port 853 user != root\n\
     block drop out inet6 proto { tcp, udp } from any to any port 853 user != root\n"
}

/// macOS's main PF ruleset evaluates `com.apple/*` for both rdr and filter rules.
/// A top-level custom anchor is loaded but never visited by that ruleset.
pub const MACOS_DNS_DIVERT_ANCHOR: &str = "com.apple/antiwire_dns";

/// A `pfctl(8)` call the macOS divert makes, and so the only ones it may make.
///
/// It touches only its own anchor and its own enable reference: never `-e` or `-d`, which
/// switch pf for the whole host, and never a `-f` or `-F` without `-a`, which would replace
/// or flush the main ruleset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacosPfctlCommand<'a> {
    /// `-E`: enables pf and takes a reference to it, whose token pfctl prints.
    Enable,
    /// `-X token`: releases the reference `token`. pf stops when no reference is left.
    Release(&'a str),
    /// `-a anchor -f -`: replaces the divert anchor's rules with the ones on standard input.
    LoadAnchor,
    /// `-a anchor -F all`: flushes the divert anchor's rules. pf deletes an anchor left empty.
    FlushAnchor,
    /// `-a anchor -sn`: the divert anchor's translation rules.
    ListAnchorTranslation,
    /// `-a anchor -sr`: the divert anchor's filter rules.
    ListAnchorFilter,
    /// `-sn`: the main ruleset's translation rules, its `rdr-anchor` among them.
    ListTranslation,
    /// `-sr`: the main ruleset's filter rules, its `anchor` among them.
    ListFilter,
    /// `-s Interfaces -v -i lo0`: `lo0`, marked when pf skips it.
    ListLoopback,
    /// `-s info`: whether pf is enabled, with its counters.
    Status,
}

impl<'a> MacosPfctlCommand<'a> {
    /// The arguments to pass to `/sbin/pfctl`.
    #[must_use]
    pub fn args(self) -> Vec<&'a str> {
        let anchor = MACOS_DNS_DIVERT_ANCHOR;
        match self {
            Self::Enable => vec!["-E"],
            Self::Release(token) => vec!["-X", token],
            Self::LoadAnchor => vec!["-a", anchor, "-f", "-"],
            Self::FlushAnchor => vec!["-a", anchor, "-F", "all"],
            Self::ListAnchorTranslation => vec!["-a", anchor, "-sn"],
            Self::ListAnchorFilter => vec!["-a", anchor, "-sr"],
            Self::ListTranslation => vec!["-sn"],
            Self::ListFilter => vec!["-sr"],
            Self::ListLoopback => vec!["-s", "Interfaces", "-v", "-i", "lo0"],
            Self::Status => vec!["-s", "info"],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_rules_skip_the_stub_and_its_marked_sockets() {
        let rules = linux_dns_divert_ruleset();
        // Once in each chain, ahead of its rules, and the only exemption there is: no
        // rule lets a user through, root included.
        let exempt = format!("meta mark {LINUX_DNS_DIVERT_EXEMPT_MARK:#010x} return");
        assert_eq!(rules.matches(exempt.as_str()).count(), 2);
        assert!(!rules.contains("skuid"));
        assert!(rules.contains("ip daddr != 127.0.0.1"));
        assert!(rules.contains("ip6 daddr != ::1"));
        assert!(rules.contains("redirect to :53"));
        assert!(rules.contains("tcp dport 853 drop"));
        assert!(rules.contains("udp dport 853 drop"));
        assert_eq!(
            linux_dns_divert_disable_args(),
            ["delete", "table", "inet", "antiwire_dns"]
        );
    }

    /// Every `nft` call names the table the ruleset creates, and loading reads the ruleset
    /// from standard input, where the divert writes it.
    #[test]
    fn linux_commands_name_the_ruleset_table() {
        let table = ["table", "inet", "antiwire_dns"];
        assert_eq!(linux_dns_divert_disable_args()[1..], table);
        assert_eq!(
            linux_dns_divert_list_args(),
            ["list", "table", "inet", "antiwire_dns"]
        );
        assert!(
            linux_dns_divert_ruleset()
                .lines()
                .any(|line| line == format!("{} {{", table.join(" ")))
        );
        assert_eq!(linux_dns_divert_install_args(), ["-f", "-"]);
    }

    /// The iptables form says what the nftables one does, once per family.
    #[test]
    fn linux_iptables_rules_skip_the_stub_and_its_marked_sockets() {
        for (family, stub) in [
            (LinuxIptablesFamily::V4, "! -d 127.0.0.1/32"),
            (LinuxIptablesFamily::V6, "! -d ::1/128"),
        ] {
            let script = linux_iptables_divert_script(family);
            let lines: Vec<&str> = script.lines().collect();
            assert_eq!(lines[0], "*nat");
            assert_eq!(lines.iter().filter(|line| **line == "COMMIT").count(), 2);
            for protocol in ["udp", "tcp"] {
                assert!(
                    lines.contains(
                        &format!(
                            "-A ANTIWIRE_DNS {stub} -p {protocol} -m {protocol} --dport 53 \
                         -j REDIRECT --to-ports 53"
                        )
                        .as_str()
                    )
                );
                assert!(
                    lines.contains(
                        &format!("-A ANTIWIRE_DNS -p {protocol} -m {protocol} --dport 853 -j DROP")
                            .as_str()
                    )
                );
            }
            // In each table the stub's marked packets return before any rule, and the
            // host's own rules come after the jump. No user is let through, root included.
            assert!(!script.contains("owner"));
            for table in ["*nat", "*filter"] {
                let start = lines.iter().position(|line| *line == table).expect(table);
                assert_eq!(lines[start + 1], ":ANTIWIRE_DNS - [0:0]");
                assert_eq!(
                    lines[start + 2],
                    format!(
                        "-A ANTIWIRE_DNS -m mark --mark {LINUX_DNS_DIVERT_EXEMPT_MARK:#x} -j RETURN"
                    )
                );
            }
            assert_eq!(
                lines
                    .iter()
                    .filter(|line| **line == "-I OUTPUT 1 -j ANTIWIRE_DNS")
                    .count(),
                2
            );
        }
        assert_eq!(
            linux_iptables_divert_install_args(),
            ["--wait", "--noflush"]
        );
    }

    /// Nothing the divert runs flushes or deletes anything but its own chain.
    #[test]
    fn linux_iptables_removal_names_only_the_divert_chain() {
        for table in LINUX_IPTABLES_DIVERT_TABLES {
            let [unhook, empty, delete] = linux_iptables_divert_remove_args(table);
            assert_eq!(
                unhook,
                ["--wait", "-t", table, "-D", "OUTPUT", "-j", "ANTIWIRE_DNS"]
            );
            assert_eq!(empty, ["--wait", "-t", table, "-F", "ANTIWIRE_DNS"]);
            assert_eq!(delete, ["--wait", "-t", table, "-X", "ANTIWIRE_DNS"]);
        }
    }

    /// Captured from `iptables-save -t nat` of iptables 1.8.11 (`nf_tables`) with the divert
    /// installed beside a rule of the host's own.
    #[test]
    fn linux_iptables_listing_keeps_the_divert_rules_and_no_counters() {
        let listing = "# Generated by iptables-save v1.8.11 (nf_tables)\n\
                       *nat\n\
                       :PREROUTING ACCEPT [0:0]\n\
                       :OUTPUT ACCEPT [12:845]\n\
                       :ANTIWIRE_DNS - [7:420]\n\
                       -A OUTPUT -j ANTIWIRE_DNS\n\
                       -A OUTPUT -d 192.0.2.1/32 -j ACCEPT\n\
                       -A ANTIWIRE_DNS -m mark --mark 0x2035 -j RETURN\n\
                       -A ANTIWIRE_DNS ! -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n\
                       COMMIT\n";
        assert_eq!(
            linux_iptables_divert_rules(listing),
            "-A OUTPUT -j ANTIWIRE_DNS\n\
             -A ANTIWIRE_DNS -m mark --mark 0x2035 -j RETURN\n\
             -A ANTIWIRE_DNS ! -d 127.0.0.1/32 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n"
        );
        assert_eq!(linux_iptables_divert_rules("*nat\nCOMMIT\n"), "");
    }

    #[test]
    fn nft_is_looked_for_only_in_system_directories() {
        for path in LINUX_NFT_PATHS {
            assert!(
                ["/usr/sbin/", "/usr/bin/", "/sbin/"]
                    .iter()
                    .any(|directory| path.strip_prefix(directory) == Some("nft")),
                "{path}"
            );
        }
        assert_eq!(LINUX_NFT_PATHS[0], "/usr/sbin/nft");
    }

    /// Each call has the arguments `pfctl(8)` gives it. None switches pf with `-e` or `-d`, and
    /// none changes rules with `-f` or `-F` outside the divert anchor, where they would replace
    /// or flush the main ruleset.
    #[test]
    fn macos_pfctl_commands_have_their_documented_arguments() {
        let anchor = MACOS_DNS_DIVERT_ANCHOR;
        for (command, args) in [
            (MacosPfctlCommand::Enable, vec!["-E"]),
            (
                MacosPfctlCommand::Release("844218394"),
                vec!["-X", "844218394"],
            ),
            (MacosPfctlCommand::LoadAnchor, vec!["-a", anchor, "-f", "-"]),
            (
                MacosPfctlCommand::FlushAnchor,
                vec!["-a", anchor, "-F", "all"],
            ),
            (
                MacosPfctlCommand::ListAnchorTranslation,
                vec!["-a", anchor, "-sn"],
            ),
            (
                MacosPfctlCommand::ListAnchorFilter,
                vec!["-a", anchor, "-sr"],
            ),
            (MacosPfctlCommand::ListTranslation, vec!["-sn"]),
            (MacosPfctlCommand::ListFilter, vec!["-sr"]),
            (
                MacosPfctlCommand::ListLoopback,
                vec!["-s", "Interfaces", "-v", "-i", "lo0"],
            ),
            (MacosPfctlCommand::Status, vec!["-s", "info"]),
        ] {
            assert_eq!(command.args(), args, "{command:?}");
            assert!(!args.contains(&"-e") && !args.contains(&"-d"), "{args:?}");
            if args.contains(&"-f") || args.contains(&"-F") {
                assert_eq!(args[..2], ["-a", anchor], "{args:?}");
            }
        }
    }

    /// The macOS rules, each split into its words.
    fn macos_rules() -> Vec<Vec<&'static str>> {
        macos_dns_divert_rules()
            .lines()
            .map(|line| line.split_whitespace().collect())
            .collect()
    }

    fn is_translation(rule: &[&str]) -> bool {
        matches!(rule.first(), Some(&("rdr" | "nat" | "binat")))
    }

    /// Whether `rule` holds `words`, next to each other and in this order.
    fn has(rule: &[&str], words: &str) -> bool {
        let words: Vec<&str> = words.split_whitespace().collect();
        rule.windows(words.len())
            .any(|window| window == words.as_slice())
    }

    /// `pf.conf(5)`'s `rdr-rule` has no `user` or `group` option. With one, pfctl rejects the
    /// whole anchor, and none of its rules load, the port 853 blocks included.
    #[test]
    fn macos_translation_rules_do_not_match_the_user() {
        let rules = macos_rules();
        let translations: Vec<_> = rules.iter().filter(|rule| is_translation(rule)).collect();
        assert!(!translations.is_empty());
        for rule in translations {
            assert!(
                !rule.contains(&"user") && !rule.contains(&"group"),
                "{rule:?}"
            );
        }
    }

    #[test]
    fn macos_translation_rules_come_before_filter_rules() {
        let rules = macos_rules();
        let filters_from = rules
            .iter()
            .position(|rule| !is_translation(rule))
            .expect("filter rules");
        assert!(
            rules[filters_from..]
                .iter()
                .all(|rule| !is_translation(rule))
        );
    }

    /// For each address family, one rule routes what a process other than root sends to port 53
    /// out of a real interface to `lo0`, and one rule sends what arrives there for an address
    /// outside loopback on to the stub. A query already addressed to the stub is left alone,
    /// and so is the stub's answer to a client on loopback: the redirect takes nothing that
    /// comes from loopback.
    #[test]
    fn macos_rules_route_bypassing_dns_to_loopback_and_redirect_it_there() {
        let rules = macos_rules();
        for (family, stub, loopback) in [
            ("inet", "127.0.0.1", "127.0.0.0/8"),
            ("inet6", "::1", "::1"),
        ] {
            let of_family = || rules.iter().filter(|rule| rule.contains(&family));
            let routes: Vec<_> = of_family()
                .filter(|rule| rule.contains(&"route-to"))
                .collect();
            let redirects: Vec<_> = of_family().filter(|rule| is_translation(rule)).collect();
            let ([route], [redirect]) = (routes.as_slice(), redirects.as_slice()) else {
                panic!("{family}: expected one route and one redirect: {routes:?} {redirects:?}");
            };
            for words in [
                "pass out quick on ! lo0",
                &format!("route-to (lo0 {stub})"),
                "proto { tcp, udp }",
                "to any port 53 user != root",
            ] {
                assert!(has(route, words), "{route:?} lacks `{words}`");
            }
            for words in [
                "rdr pass on lo0",
                "proto { tcp, udp }",
                &format!("from ! {loopback} to ! {loopback} port 53"),
                &format!("-> {stub} port 53"),
            ] {
                assert!(has(redirect, words), "{redirect:?} lacks `{words}`");
            }
        }
    }

    /// A tag set as a packet leaves is cleared before the packet arrives on `lo0` (see
    /// [`macos_dns_divert_rules`]), so a rule waiting for one matches nothing: with such a
    /// rule every diverted query was routed to `lo0` and dropped there.
    #[test]
    fn macos_rules_do_not_depend_on_a_tag() {
        for rule in macos_rules() {
            assert!(
                !rule.contains(&"tag") && !rule.contains(&"tagged"),
                "{rule:?}"
            );
        }
    }

    #[test]
    fn macos_rules_drop_port_853_for_everyone_but_root() {
        let rules = macos_rules();
        for family in ["inet", "inet6"] {
            assert!(
                rules.iter().any(|rule| rule.contains(&family)
                    && has(rule, "block drop out")
                    && has(rule, "port 853 user != root")),
                "{family}"
            );
        }
    }

    /// macOS's main ruleset reaches anchors only through `com.apple/*`.
    #[test]
    fn macos_anchor_sits_where_the_main_ruleset_looks() {
        assert!(MACOS_DNS_DIVERT_ANCHOR.starts_with("com.apple/"));
    }
}
