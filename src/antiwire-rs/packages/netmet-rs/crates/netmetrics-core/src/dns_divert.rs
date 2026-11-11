//! Port-53 divert rules shared by the platform backends.
//!
//! The strings are platform commands, but they contain no OS calls, so the
//! Windows test suite can still check that shutdown removes the rule.

/// nftables script installed while the stub is running.
///
/// Root's own queries are returned unchanged so the stub can still reach an
/// upstream resolver. Traffic already addressed to the stub is not matched.
#[must_use]
pub fn linux_dns_divert_ruleset() -> &'static str {
    "table inet antiwire_dns\n\
     delete table inet antiwire_dns\n\
     table inet antiwire_dns {\n\
     \tchain output {\n\
     \t\ttype nat hook output priority dstnat; policy accept;\n\
     \t\tmeta skuid 0 return\n\
     \t\tudp dport 53 ip daddr != 127.0.0.1 redirect to :53\n\
     \t\ttcp dport 53 ip daddr != 127.0.0.1 redirect to :53\n\
     \t\tudp dport 53 ip6 daddr != ::1 redirect to :53\n\
     \t\ttcp dport 53 ip6 daddr != ::1 redirect to :53\n\
     \t}\n\
     \tchain output_filter {\n\
     \t\ttype filter hook output priority filter; policy accept;\n\
     \t\tmeta skuid 0 return\n\
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

/// pf anchor rules for locally generated DNS that is not already aimed at the stub.
#[must_use]
pub fn macos_dns_divert_rules() -> &'static str {
    "rdr pass inet proto { tcp, udp } from any to ! 127.0.0.1 port 53 user != root -> 127.0.0.1 port 53\n\
     rdr pass inet6 proto { tcp, udp } from any to ! ::1 port 53 user != root -> ::1 port 53\n\
     block drop out inet proto { tcp, udp } from any to any port 853 user != root\n\
     block drop out inet6 proto { tcp, udp } from any to any port 853 user != root\n"
}

/// macOS's main PF ruleset evaluates `com.apple/*` for both rdr and filter rules.
/// A top-level custom anchor is loaded but never visited by that ruleset.
pub const MACOS_DNS_DIVERT_ANCHOR: &str = "com.apple/antiwire_dns";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_rules_skip_the_stub_and_the_root_resolver() {
        let rules = linux_dns_divert_ruleset();
        assert!(rules.contains("meta skuid 0 return"));
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

    #[test]
    fn macos_rules_skip_root_and_the_stub_and_name_the_anchor() {
        let rules = macos_dns_divert_rules();
        assert!(rules.contains("user != root"));
        assert!(rules.contains("to ! 127.0.0.1 port 53"));
        assert!(rules.contains("to ! ::1 port 53"));
        assert!(rules.contains("port 853 user != root"));
        assert_eq!(MACOS_DNS_DIVERT_ANCHOR, "com.apple/antiwire_dns");
    }
}
