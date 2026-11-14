//! Pure policy evaluation: firewall rules, blocklists, hosts parsing, and enforcement intents.

mod app_identity;
mod blocklist;
mod blocklist_catalog;
mod blocklist_display;
mod blocklist_line;
mod blocklist_sync_frequency;
mod display;
mod eviction;
mod hash;
mod hosts;
mod normalize;
mod recent;
mod rule;
mod rule_engine;
mod rule_index;

pub use app_identity::{
    app_rule_identity, is_synthetic_placeholder, is_unknown_placeholder, stable_identity,
    BASENAME_FALLBACK_PATH, UNKNOWN_APP_NAME,
};
pub use blocklist::{BlocklistBuilder, PreparedBlocklist};
pub use blocklist_catalog::{
    blocklist_sync_allow_hosts, estimate_blocklist_size, is_builtin_list_id, resolve_sync_targets,
    SyncTarget, SYSTEM_HOSTS_LIST_ID,
};
pub use blocklist_sync_frequency::blocklist_sync_interval_hours;
pub use display::display_text;
pub use eviction::EnforcementOp;
pub use hosts::{HostsParser, HostsParserMode};
pub use normalize::normalize_rule;
pub use recent::RecentLru;
pub use rule::{CountrySnapshot, RuleDirection, RuleSnapshot, RuleTargetKind, TargetType, Verdict};
pub use rule_engine::{
    DnsPolicyView, DomainBlockSource, DomainDecision, PolicyEngine, PublishedDnsPolicyHandle,
    RuleEngine, AI_BLOCK_LABEL, FIREWALL_RULE_LABEL, LOADING_BLOCKLISTS_LABEL,
};
