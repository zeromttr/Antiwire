//! Embedded libSQL persistence for the Antiwire daemon.

#![allow(clippy::missing_errors_doc)]

mod crypto;
mod db;
mod dns_front;
mod domain_evidence;
mod error;
mod models;
mod store;

pub use dns_front::dns_inference_eligible;
pub use domain_evidence::{
    domain_evidence, domain_is_inferred, prefer_dst_domain, DomainEvidence, INFERRED_SUFFIX,
};

pub use antiwire_secrets::SecretBytes;
pub use error::{Result, StoreError};
pub use models::normalize_update_channel;
pub use models::{
    activity_bucket_start, clamp_ai_confidence, decode_blocklist_names, encode_blocklist_names,
    ActivityBucket, Alert, Application, ApplicationLogSummary, ApplicationLogSummaryQuery,
    ApplicationSighting, ConnectionDomainUpgrade, ConnectionLog, ConnectionLogAttribution,
    ConnectionLogPage, ConnectionLogQuery, CountryStatistics, DaemonSetting, DnsBypass,
    DnsCacheEntry, DomainDecision, DomainDecisionPage, DomainDecisionQuery,
    DomainDecisionVerdictFilter, DomainLookup, FirewallRule, NetworkDevice, NetworkDeviceWatch,
    NetworkScanRange, NewAlert, NewConnectionLog, ACTIVITY_BUCKET_SECONDS, MIN_AI_CONFIDENCE,
};
pub use store::{
    normalize_domain_key, DeletionFence, OutcomeRevision, Resident, ResidentDecision,
    SeenSubdomain, Store,
};
